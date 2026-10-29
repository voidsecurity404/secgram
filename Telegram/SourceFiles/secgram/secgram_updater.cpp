/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "secgram/secgram_updater.h"

#include "base/options.h"
#include "core/application.h"
#include "core/file_utilities.h"
#include "lang/lang_keys.h"
#include "settings.h"
#include "ui/layers/generic_box.h"
#include "ui/text/text_utilities.h"
#include "ui/widgets/labels.h"
#include "window/window_session_controller.h"

#include "styles/style_layers.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QProcess>
#include <QtCore/QRegularExpression>
#include <QtCore/QStandardPaths>
#include <QtCore/QTimer>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtWidgets/QApplication>

namespace SecGram {
namespace {

constexpr auto kRepo = "voidsecurity404/secgram";
constexpr auto kCheckInterval = 12 * 60 * 60;
constexpr auto kStartDelay = 15 * crl::time(1000);

base::options::toggle UpdateCheck({
	.id = kOptionUpdateCheck,
	.name = "Проверять обновления SecGram",
	.description = "Раз в 12 часов проверять GitHub Releases SecGram "
		"и предлагать установить новую версию.",
	.defaultValue = true,
});

struct Asset {
	QString name;
	QString url;
	qint64 size = 0;
};

struct Release {
	QString version;
	QString notes;
	std::vector<Asset> assets;
};

enum class InstallKind {
	InPlace, // tar.xz / portable folder we can write to.
	Deb,
	Rpm,
	Manual, // Arch PKGBUILD, Windows for now, or anything else.
};

[[nodiscard]] QNetworkAccessManager *Manager() {
	static auto result = (QNetworkAccessManager*)nullptr;
	if (!result) {
		result = new QNetworkAccessManager(qApp);
	}
	return result;
}

[[nodiscard]] QString StatePath() {
	return cWorkingDir() + u"tdata/secgram/update_state.json"_q;
}

[[nodiscard]] QJsonObject ReadState() {
	auto file = QFile(StatePath());
	return file.open(QIODevice::ReadOnly)
		? QJsonDocument::fromJson(file.readAll()).object()
		: QJsonObject();
}

void WriteState(const QJsonObject &state) {
	QDir().mkpath(QFileInfo(StatePath()).absolutePath());
	auto file = QFile(StatePath());
	if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
		file.write(QJsonDocument(state).toJson(QJsonDocument::Compact));
	}
}

// 1.2.10 > 1.2.9, a missing part counts as 0.
[[nodiscard]] int Compare(const QString &a, const QString &b) {
	const auto x = QString(a).remove(QRegularExpression("^v")).split(
		QRegularExpression("[.-]"));
	const auto y = QString(b).remove(QRegularExpression("^v")).split(
		QRegularExpression("[.-]"));
	for (auto i = 0; i != std::max(x.size(), y.size()); ++i) {
		const auto p = (i < x.size()) ? x[i].toInt() : 0;
		const auto q = (i < y.size()) ? y[i].toInt() : 0;
		if (p != q) {
			return (p < q) ? -1 : 1;
		}
	}
	return 0;
}

[[nodiscard]] QNetworkRequest Request(const QString &url) {
	auto request = QNetworkRequest(QUrl(url));
	request.setAttribute(
		QNetworkRequest::RedirectPolicyAttribute,
		QNetworkRequest::NoLessSafeRedirectPolicy);
	request.setHeader(
		QNetworkRequest::UserAgentHeader,
		u"SecGram-Desktop/"_q + QString::fromLatin1(kVersion));
	request.setTransferTimeout(60000);
	return request;
}

[[nodiscard]] InstallKind DetectInstallKind() {
#ifdef Q_OS_LINUX
	if (QFileInfo(cExeDir()).isWritable()
		&& QFileInfo(cExeDir() + cExeName()).isWritable()) {
		return InstallKind::InPlace;
	}
	auto file = QFile(u"/etc/os-release"_q);
	const auto release = file.open(QIODevice::ReadOnly)
		? QString::fromUtf8(file.readAll()).toLower()
		: QString();
	const auto like = [&](const char *name) {
		return QRegularExpression(
			u"^(id|id_like)=.*\\b"_q + QString::fromLatin1(name) + u"\\b"_q,
			QRegularExpression::MultilineOption).match(release).hasMatch();
	};
	if (like("debian") || like("ubuntu")) {
		return InstallKind::Deb;
	} else if (like("fedora") || like("rhel") || like("centos")
		|| like("suse")) {
		return InstallKind::Rpm;
	}
#endif // Q_OS_LINUX
	return InstallKind::Manual;
}

[[nodiscard]] const Asset *FindAsset(
		const Release &release,
		const QString &suffix) {
	for (const auto &asset : release.assets) {
		if (asset.name.endsWith(suffix)) {
			return &asset;
		}
	}
	return nullptr;
}

void FetchLatest(Fn<void(std::optional<Release>, QString)> done) {
	const auto reply = Manager()->get(Request(
		u"https://api.github.com/repos/"_q
		+ QString::fromLatin1(kRepo)
		+ u"/releases/latest"_q));
	QObject::connect(reply, &QNetworkReply::finished, [=] {
		reply->deleteLater();
		if (reply->error() != QNetworkReply::NoError) {
			done(std::nullopt, reply->errorString());
			return;
		}
		const auto json = QJsonDocument::fromJson(reply->readAll()).object();
		auto release = Release{
			.version = json.value(u"tag_name"_q).toString().remove(
				QRegularExpression("^v")),
			.notes = json.value(u"body"_q).toString(),
		};
		const auto prefix = u"https://github.com/"_q
			+ QString::fromLatin1(kRepo)
			+ u"/releases/download/"_q;
		for (const auto &value : json.value(u"assets"_q).toArray()) {
			const auto asset = value.toObject();
			const auto url = asset.value(u"browser_download_url"_q).toString();
			// Only files of this repository's releases are accepted.
			if (url.startsWith(prefix)) {
				release.assets.push_back({
					.name = asset.value(u"name"_q).toString(),
					.url = url,
					.size = asset.value(u"size"_q).toInteger(),
				});
			}
		}
		done(release, QString());
	});
}

void Download(
		const QString &url,
		Fn<void(QByteArray, QString)> done) {
	const auto reply = Manager()->get(Request(url));
	QObject::connect(reply, &QNetworkReply::finished, [=] {
		reply->deleteLater();
		if (reply->error() != QNetworkReply::NoError) {
			done(QByteArray(), reply->errorString());
		} else {
			done(reply->readAll(), QString());
		}
	});
}

// Looks the file up in SHA256SUMS.txt of the same release.
[[nodiscard]] QString VerifyChecksum(
		const QByteArray &sums,
		const QString &name,
		const QByteArray &data) {
	const auto actual = QString::fromLatin1(QCryptographicHash::hash(
		data,
		QCryptographicHash::Sha256).toHex());
	for (const auto &line : QString::fromUtf8(sums).split('\n')) {
		const auto parts = line.simplified().split(' ');
		if (parts.size() == 2 && QString(parts[1]).remove('*') == name) {
			return (parts[0].toLower() == actual)
				? QString()
				: u"контрольная сумма не совпадает"_q;
		}
	}
	return u"файл не найден в SHA256SUMS.txt"_q;
}

void ShowText(
		not_null<Window::SessionController*> controller,
		const QString &title,
		const QString &text) {
	controller->show(Box([=](not_null<Ui::GenericBox*> box) {
		box->setTitle(rpl::single(title));
		box->setWidth(st::boxWideWidth);
		const auto label = box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			text,
			st::boxLabel));
		label->setSelectable(true);
		box->addButton(tr::lng_close(), [=] { box->closeBox(); });
	}));
}

void InstallInPlace(
		not_null<Window::SessionController*> controller,
		const Release &release,
		const Asset &archive,
		const Asset &sums) {
	controller->showToast(u"Загрузка SecGram %1…"_q.arg(release.version));
	const auto weak = base::make_weak(controller);
	Download(sums.url, [=](QByteArray sumsData, QString error) {
		if (!error.isEmpty()) {
			if (const auto strong = weak.get()) {
				strong->showToast(u"Ошибка обновления: "_q + error);
			}
			return;
		}
		Download(archive.url, [=](QByteArray data, QString error) {
			const auto strong = weak.get();
			if (!strong) {
				return;
			}
			if (error.isEmpty()) {
				error = VerifyChecksum(sumsData, archive.name, data);
			}
			const auto folder = cWorkingDir() + u"tdata/secgram/update/"_q;
			QDir(folder).removeRecursively();
			QDir().mkpath(folder);
			const auto path = folder + archive.name;
			if (error.isEmpty()) {
				auto file = QFile(path);
				if (!file.open(QIODevice::WriteOnly)
					|| file.write(data) != data.size()) {
					error = u"не удалось сохранить архив"_q;
				}
			}
			if (error.isEmpty()
				&& QProcess::execute(
					u"tar"_q,
					{ u"-xJf"_q, path, u"-C"_q, folder }) != 0) {
				error = u"не удалось распаковать архив"_q;
			}
			const auto fresh = folder + u"SecGram/SecGram"_q;
			const auto current = cExeDir() + cExeName();
			if (error.isEmpty() && !QFileInfo::exists(fresh)) {
				error = u"в архиве нет программы"_q;
			}
			if (error.isEmpty()) {
				QFile::remove(current + u".old"_q);
				if (!QFile::rename(current, current + u".old"_q)
					|| !QFile::copy(fresh, current)) {
					QFile::rename(current + u".old"_q, current);
					error = u"не удалось заменить программу"_q;
				} else {
					QFile(current).setPermissions(
						QFile(current + u".old"_q).permissions());
				}
			}
			if (!error.isEmpty()) {
				strong->showToast(u"Ошибка обновления: "_q + error);
				return;
			}
			strong->show(Box([=](not_null<Ui::GenericBox*> box) {
				box->setTitle(rpl::single(u"SecGram обновлён"_q));
				box->addRow(object_ptr<Ui::FlatLabel>(
					box,
					u"Установлена версия %1. Перезапустить SecGram сейчас?"_q
						.arg(release.version),
					st::boxLabel));
				box->addButton(rpl::single(u"Перезапустить"_q), [] {
					Core::Restart();
				});
				box->addButton(rpl::single(u"Позже"_q), [=] {
					box->closeBox();
				});
			}));
		});
	});
}

void InstallPackage(
		not_null<Window::SessionController*> controller,
		const Release &release,
		const Asset &package,
		const Asset &sums,
		InstallKind kind) {
	controller->showToast(u"Загрузка "_q + package.name + u"…"_q);
	const auto weak = base::make_weak(controller);
	Download(sums.url, [=](QByteArray sumsData, QString error) {
		Download(package.url, [=](QByteArray data, QString error2) {
			const auto strong = weak.get();
			if (!strong) {
				return;
			}
			auto failure = !error.isEmpty() ? error : error2;
			if (failure.isEmpty()) {
				failure = VerifyChecksum(sumsData, package.name, data);
			}
			const auto folder = QStandardPaths::writableLocation(
				QStandardPaths::DownloadLocation);
			const auto path = folder + '/' + package.name;
			if (failure.isEmpty()) {
				QDir().mkpath(folder);
				auto file = QFile(path);
				if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)
					|| file.write(data) != data.size()) {
					failure = u"не удалось сохранить файл"_q;
				}
			}
			if (!failure.isEmpty()) {
				strong->showToast(u"Ошибка обновления: "_q + failure);
				return;
			}
			const auto command = (kind == InstallKind::Deb)
				? (u"sudo apt install \""_q + path + '"')
				: (u"sudo dnf install \""_q + path + '"');
			ShowText(
				strong,
				u"Обновление SecGram %1 загружено"_q.arg(release.version),
				u"Файл проверен (SHA-256) и сохранён:\n%1\n\n"
				"Установите его через центр приложений (откроется сейчас) "
				"или командой:\n%2\n\nЧаты и настройки сохранятся."_q.arg(
					path,
					command));
			File::Launch(path);
		});
	});
}

void Offer(
		not_null<Window::SessionController*> controller,
		const Release &release) {
	const auto kind = DetectInstallKind();
	const auto sums = FindAsset(release, u"SHA256SUMS.txt"_q);
	const auto archive = FindAsset(release, u"-linux-x86_64.tar.xz"_q);
	const auto deb = FindAsset(release, u"_amd64.deb"_q);
	const auto rpm = FindAsset(release, u".x86_64.rpm"_q);
	auto text = TextWithEntities{ u"Доступна новая версия SecGram %1 "
		"(у вас %2)."_q.arg(release.version, QString::fromLatin1(kVersion)) };
	if (!release.notes.trimmed().isEmpty()) {
		text.append(u"\n\n"_q).append(Ui::Text::Bold(u"Что нового:"_q));
		text.append('\n').append(release.notes.trimmed().left(1500));
	}
	text.append(u"\n\nЧаты и настройки сохранятся."_q);
	const auto copy = release;
	controller->show(Box([=](not_null<Ui::GenericBox*> box) {
		box->setTitle(rpl::single(u"Обновление SecGram"_q));
		box->setWidth(st::boxWideWidth);
		box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			rpl::single(text),
			st::boxLabel));
		const auto releasePage = u"https://github.com/"_q
			+ QString::fromLatin1(kRepo)
			+ u"/releases/latest"_q;
		const auto weak = base::make_weak(controller);
		box->addButton(rpl::single(u"Обновить"_q), [=] {
			box->closeBox();
			const auto strong = weak.get();
			if (!strong) {
				return;
			} else if (kind == InstallKind::InPlace && archive && sums) {
				InstallInPlace(strong, copy, *archive, *sums);
			} else if (kind == InstallKind::Deb && deb && sums) {
				InstallPackage(strong, copy, *deb, *sums, kind);
			} else if (kind == InstallKind::Rpm && rpm && sums) {
				InstallPackage(strong, copy, *rpm, *sums, kind);
			} else {
				File::OpenUrl(releasePage);
			}
		});
		box->addButton(rpl::single(u"Позже"_q), [=] { box->closeBox(); });
		box->addLeftButton(rpl::single(u"Пропустить версию"_q), [=] {
			auto state = ReadState();
			state.insert(u"skipped"_q, copy.version);
			WriteState(state);
			box->closeBox();
		});
	}));
}

void Check(
		not_null<Window::SessionController*> controller,
		bool manual) {
	const auto weak = base::make_weak(controller);
	FetchLatest([=](std::optional<Release> release, QString error) {
		const auto strong = weak.get();
		if (!strong) {
			return;
		} else if (!release || release->version.isEmpty()) {
			if (manual) {
				strong->showToast(u"Не удалось проверить обновления: "_q
					+ error);
			}
			return;
		}
		const auto newer = Compare(
			release->version,
			QString::fromLatin1(kVersion)) > 0;
		const auto skipped = ReadState().value(u"skipped"_q).toString()
			== release->version;
		if (!newer) {
			if (manual) {
				strong->showToast(u"У вас последняя версия SecGram "_q
					+ QString::fromLatin1(kVersion));
			}
		} else if (!skipped || manual) {
			Offer(strong, *release);
		}
	});
}

} // namespace

const char kOptionUpdateCheck[] = "secgram-update-check";

void CheckForUpdatesLater(
		not_null<Window::SessionController*> controller) {
	static auto scheduled = false;
	if (scheduled || !UpdateCheck.value()) {
		return;
	}
	scheduled = true;
	const auto weak = base::make_weak(controller);
	QTimer::singleShot(kStartDelay, qApp, [=] {
		const auto strong = weak.get();
		if (!strong) {
			return;
		}
		auto state = ReadState();
		const auto now = QDateTime::currentSecsSinceEpoch();
		if (now - state.value(u"checked"_q).toInteger() < kCheckInterval) {
			return;
		}
		state.insert(u"checked"_q, now);
		WriteState(state);
		Check(strong, false);
	});
}

void CheckForUpdatesNow(not_null<Window::SessionController*> controller) {
	Check(controller, true);
}

} // namespace SecGram
