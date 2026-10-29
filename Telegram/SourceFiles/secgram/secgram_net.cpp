/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "secgram/secgram_net.h"

#include "settings.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QHash>
#include <QtCore/QDateTime>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QTimer>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QSslCertificate>
#include <QtNetwork/QSslSocket>

namespace SecGram {
namespace {

constexpr auto kTimeout = 12000;
constexpr auto kYoungDomainDays = 30;
constexpr auto kNewDomainDays = 180;

[[nodiscard]] QNetworkAccessManager *Manager() {
	static auto result = (QNetworkAccessManager*)nullptr;
	if (!result) {
		result = new QNetworkAccessManager(qApp);
	}
	return result;
}

void CheckRdap(const QString &domain, Fn<void(ServerCheck)> done) {
	auto request = QNetworkRequest(
		QUrl(u"https://rdap.org/domain/"_q + domain));
	request.setAttribute(
		QNetworkRequest::RedirectPolicyAttribute,
		QNetworkRequest::NoLessSafeRedirectPolicy);
	request.setTransferTimeout(kTimeout);
	request.setRawHeader("Accept", "application/rdap+json");
	const auto reply = Manager()->get(request);
	QObject::connect(reply, &QNetworkReply::finished, [=] {
		reply->deleteLater();
		auto result = ServerCheck();
		if (reply->error() != QNetworkReply::NoError) {
			result.details.push_back(u"RDAP: нет данных (%1)"_q.arg(
				reply->errorString()));
			done(std::move(result));
			return;
		}
		const auto json = QJsonDocument::fromJson(reply->readAll()).object();
		auto registered = QDateTime();
		auto expires = QDateTime();
		for (const auto &value : json.value(u"events"_q).toArray()) {
			const auto event = value.toObject();
			const auto action = event.value(u"eventAction"_q).toString();
			const auto date = QDateTime::fromString(
				event.value(u"eventDate"_q).toString(),
				Qt::ISODate);
			if (action == u"registration"_q) {
				registered = date;
			} else if (action == u"expiration"_q) {
				expires = date;
			}
		}
		auto registrar = QString();
		for (const auto &value : json.value(u"entities"_q).toArray()) {
			const auto entity = value.toObject();
			const auto roles = entity.value(u"roles"_q).toArray();
			if (!roles.contains(u"registrar"_q)) {
				continue;
			}
			const auto vcard = entity.value(u"vcardArray"_q).toArray();
			for (const auto &field : vcard.at(1).toArray()) {
				const auto parts = field.toArray();
				if (parts.at(0).toString() == u"fn"_q) {
					registrar = parts.at(3).toString();
				}
			}
		}
		if (registered.isValid()) {
			const auto days = registered.daysTo(
				QDateTime::currentDateTimeUtc());
			result.details.push_back(
				u"Домен зарегистрирован: %1 (%2 дн. назад)"_q.arg(
					registered.toString(u"yyyy-MM-dd"_q),
					QString::number(days)));
			if (days < kYoungDomainDays) {
				result.report.add(
					Severity::High,
					u"Домен создан всего %1 дн. назад — фишинговые сайты "
						"почти всегда совсем новые."_q.arg(days));
			} else if (days < kNewDomainDays) {
				result.report.add(
					Severity::Notice,
					u"Домену меньше полугода (%1 дн.)."_q.arg(days));
			}
		}
		if (expires.isValid()) {
			result.details.push_back(u"Истекает: %1"_q.arg(
				expires.toString(u"yyyy-MM-dd"_q)));
		}
		if (!registrar.isEmpty()) {
			result.details.push_back(u"Регистратор: "_q + registrar);
		}
		done(std::move(result));
	});
}

void CheckTls(const QString &host, Fn<void(ServerCheck)> done) {
	const auto socket = new QSslSocket(qApp);
	const auto errors = std::make_shared<QList<QSslError>>();
	const auto finished = std::make_shared<bool>(false);
	const auto finish = [=] {
		if (*finished) {
			return;
		}
		*finished = true;
		auto result = ServerCheck();
		const auto chain = socket->peerCertificateChain();
		const auto cert = chain.isEmpty()
			? socket->peerCertificate()
			: chain.front();
		if (cert.isNull()) {
			result.details.push_back(u"TLS: не удалось получить "
				"сертификат (%1)"_q.arg(socket->errorString()));
		} else {
			const auto issuer = cert.issuerInfo(
				QSslCertificate::Organization).join(u", "_q);
			const auto issued = cert.effectiveDate();
			const auto days = issued.daysTo(QDateTime::currentDateTimeUtc());
			auto names = QStringList();
			for (const auto &name : cert.subjectAlternativeNames()) {
				names.push_back(name);
			}
			result.details.push_back(u"Сертификат выдан: %1, %2 (%3 дн. "
				"назад), до %4"_q.arg(
					issuer.isEmpty() ? u"?"_q : issuer,
					issued.toString(u"yyyy-MM-dd"_q),
					QString::number(days),
					cert.expiryDate().toString(u"yyyy-MM-dd"_q)));
			if (!names.isEmpty()) {
				result.details.push_back(u"Домены в сертификате: "_q
					+ names.mid(0, 8).join(u", "_q)
					+ (names.size() > 8 ? u" …"_q : QString()));
			}
			if (days < 3) {
				result.report.add(
					Severity::Notice,
					u"Сертификат выпущен меньше 3 дней назад."_q);
			}
		}
		if (!errors->isEmpty()) {
			auto texts = QStringList();
			for (const auto &error : *errors) {
				texts.push_back(error.errorString());
			}
			result.report.add(
				Severity::High,
				u"Ошибки сертификата: "_q + texts.join(u"; "_q));
		}
		socket->abort();
		socket->deleteLater();
		done(std::move(result));
	};
	QObject::connect(
		socket,
		&QSslSocket::sslErrors,
		[=](const QList<QSslError> &list) {
			*errors = list;
			socket->ignoreSslErrors(); // Only to read the certificate.
		});
	QObject::connect(socket, &QSslSocket::encrypted, finish);
	QObject::connect(socket, &QAbstractSocket::errorOccurred, finish);
	QTimer::singleShot(kTimeout, socket, finish);
	socket->connectToHostEncrypted(host, 443);
}

struct Feeds {
	QHash<QString, QString> hosts; // Host -> source, only for hosts that
	// are not shared hosting (feeds contain full urls too).
	QHash<QString, QString> urls;
	QDateTime updated;
	bool loaded = false;
};

[[nodiscard]] QString FeedsPath() {
	return QCoreApplication::applicationDirPath().isEmpty()
		? QString()
		: (cWorkingDir() + u"tdata/secgram/feeds.txt"_q);
}

Feeds &FeedsData() {
	static auto result = Feeds();
	if (!result.loaded) {
		result.loaded = true;
		auto file = QFile(FeedsPath());
		if (file.open(QIODevice::ReadOnly)) {
			result.updated = QFileInfo(file).lastModified();
			while (!file.atEnd()) {
				const auto line = QString::fromUtf8(file.readLine()).trimmed();
				const auto parts = line.split('\t');
				if (parts.size() != 3) {
					continue;
				}
				if (parts[1] == u"host"_q) {
					result.hosts.insert(parts[2], parts[0]);
				} else {
					result.urls.insert(parts[2], parts[0]);
				}
			}
		}
	}
	return result;
}

[[nodiscard]] QString NormalizeFeedUrl(const QString &url) {
	auto parsed = QUrl(url.trimmed());
	parsed.setFragment(QString());
	auto result = QString::fromUtf8(parsed.toEncoded()).toLower();
	while (result.endsWith('/')) {
		result.chop(1);
	}
	return result;
}

} // namespace

void UpdateThreatFeeds(Fn<void(int count, QString error)> done) {
	struct Source {
		QString name;
		QString url;
	};
	const auto sources = std::vector<Source>{
		{ u"OpenPhish"_q, u"https://openphish.com/feed.txt"_q },
		// URLhaus downloads need an Auth-Key now, Phishing Army is free.
		{ u"Phishing Army"_q, u"https://phishing.army/download/phishing_army_blocklist.txt"_q },
	};
	const auto collected = std::make_shared<QStringList>();
	const auto errors = std::make_shared<QStringList>();
	const auto left = std::make_shared<int>(int(sources.size()));
	const auto finish = [=] {
		if (--*left) {
			return;
		}
		if (collected->isEmpty()) {
			done(0, errors->join(u"; "_q));
			return;
		}
		QDir().mkpath(QFileInfo(FeedsPath()).absolutePath());
		auto file = QFile(FeedsPath());
		if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
			done(0, u"не удалось сохранить базу"_q);
			return;
		}
		file.write(collected->join('\n').toUtf8());
		file.close();
		FeedsData() = Feeds();
		done(FeedsData().urls.size(), errors->join(u"; "_q));
	};
	for (const auto &source : sources) {
		auto request = QNetworkRequest(QUrl(source.url));
		request.setTransferTimeout(30000);
		request.setAttribute(
			QNetworkRequest::RedirectPolicyAttribute,
			QNetworkRequest::NoLessSafeRedirectPolicy);
		const auto reply = Manager()->get(request);
		const auto name = source.name;
		QObject::connect(reply, &QNetworkReply::finished, [=] {
			reply->deleteLater();
			if (reply->error() != QNetworkReply::NoError) {
				errors->push_back(name + u": "_q + reply->errorString());
				finish();
				return;
			}
			auto hostCounts = QHash<QString, int>();
			auto urls = QStringList();
			for (const auto &raw : QString::fromUtf8(
					reply->readAll()).split('\n')) {
				const auto line = raw.trimmed();
				if (line.isEmpty() || line.startsWith('#')) {
					continue;
				}
				if (!line.contains(u"://"_q)) {
					// Plain domain list.
					collected->push_back(
						name + u"\thost\t"_q + line.toLower());
					continue;
				}
				urls.push_back(line);
				++hostCounts[QUrl(line).host().toLower()];
			}
			for (const auto &url : urls) {
				collected->push_back(
					name + u"\turl\t"_q + NormalizeFeedUrl(url));
			}
			// A host is listed as a whole only when it is not a big
			// shared service (those appear in feeds with one bad path).
			for (auto i = hostCounts.begin(); i != hostCounts.end(); ++i) {
				const auto shared = RegistrableDomain(i.key()) != i.key()
					&& QStringList{
						u"google.com"_q, u"github.io"_q, u"github.com"_q,
						u"dropbox.com"_q, u"microsoft.com"_q,
						u"docs.google.com"_q, u"sharepoint.com"_q,
						u"blogspot.com"_q, u"weebly.com"_q,
						u"wixsite.com"_q, u"pages.dev"_q,
						u"workers.dev"_q, u"vercel.app"_q,
						u"netlify.app"_q, u"web.app"_q,
						u"firebaseapp.com"_q, u"r2.dev"_q,
					}.contains(RegistrableDomain(i.key()));
				if (!i.key().isEmpty() && !shared) {
					collected->push_back(name + u"\thost\t"_q + i.key());
				}
			}
			finish();
		});
	}
}

QString ThreatFeedMatch(const QString &url) {
	auto &feeds = FeedsData();
	if (feeds.urls.isEmpty() && feeds.hosts.isEmpty()) {
		return QString();
	}
	const auto normalized = NormalizeFeedUrl(url);
	if (const auto i = feeds.urls.find(normalized); i != feeds.urls.end()) {
		return i.value();
	}
	auto host = QUrl(url).host().toLower();
	while (!host.isEmpty()) {
		if (const auto i = feeds.hosts.find(host); i != feeds.hosts.end()) {
			return i.value();
		}
		const auto dot = host.indexOf('.');
		if (dot < 0) {
			break;
		}
		host = host.mid(dot + 1);
	}
	return QString();
}

QString ThreatFeedsInfo() {
	const auto &feeds = FeedsData();
	return feeds.updated.isValid()
		? u"%1 адресов, %2 хостов, обновлено %3"_q.arg(
			QString::number(feeds.urls.size()),
			QString::number(feeds.hosts.size()),
			feeds.updated.toString(u"yyyy-MM-dd HH:mm"_q))
		: u"база не загружена"_q;
}

void CheckServer(const QString &host, Fn<void(ServerCheck)> done) {
	const auto state = std::make_shared<ServerCheck>();
	const auto left = std::make_shared<int>(2);
	const auto merge = [=](ServerCheck part) {
		for (auto &finding : part.report.findings) {
			state->report.findings.push_back(std::move(finding));
		}
		state->details.append(part.details);
		if (!--*left) {
			done(std::move(*state));
		}
	};
	CheckRdap(RegistrableDomain(host), merge);
	CheckTls(host, merge);
}

} // namespace SecGram
