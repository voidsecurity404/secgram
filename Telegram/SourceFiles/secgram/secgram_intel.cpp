/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "secgram/secgram_intel.h"

#include "apiwrap.h"
#include "base/options.h"
#include "base/unixtime.h"
#include "core/application.h"
#include "core/file_utilities.h"
#include "data/data_document.h"
#include "data/data_media_types.h"
#include "data/data_peer.h"
#include "data/data_photo.h"
#include "data/data_photo_media.h"
#include "data/data_session.h"
#include "history/history.h"
#include "history/history_item.h"
#include "history/history_item_components.h"
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "secgram/secgram_analyzer.h"
#include "secgram/secgram_ui.h"
#include "secgram/secgram_tools.h"
#include "secgram/secgram_crypto.h"
#include "settings.h"
#include "ui/image/image.h"
#include "ui/layers/generic_box.h"
#include "ui/layers/show.h"
#include "ui/text/text_utilities.h"
#include "ui/toast/toast.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/widgets/labels.h"
#include "window/window_controller.h"
#include "window/window_session_controller.h"

#include "styles/style_boxes.h"
#include "styles/style_layers.h"
#include "styles/style_widgets.h"

#include <QtCore/QBuffer>
#include <QtCore/QCryptographicHash>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QRegularExpression>
#include <QtCore/QStandardPaths>
#include <QtCore/QSysInfo>
#include <QtWidgets/QApplication>

namespace SecGram {
namespace {

constexpr auto kShownHits = 100;

base::options::toggle Watchlist({
	.id = kOptionWatchlist,
	.name = "Список наблюдения",
	.description = "Уведомлять, когда в любом чате появляется слово, домен, "
		"IP, кошелёк или другой индикатор из списка наблюдения.",
	.defaultValue = true,
});

struct Term {
	QString text;
	std::optional<QRegularExpression> regex;
};

[[nodiscard]] QString WatchlistPath() {
	return cWorkingDir() + u"tdata/secgram/watchlist.txt"_q;
}

[[nodiscard]] QString HitsPath(not_null<Main::Session*> session) {
	return cWorkingDir()
		+ u"tdata/secgram/"_q
		+ QString::number(session->userId().bare)
		+ u"/watch_hits.jsonl"_q;
}

[[nodiscard]] QString ReadWatchlistText() {
	auto file = QFile(WatchlistPath());
	return file.open(QIODevice::ReadOnly)
		? QString::fromUtf8(file.readAll())
		: QString();
}

[[nodiscard]] std::vector<Term> ParseTerms(const QString &text) {
	auto result = std::vector<Term>();
	for (auto line : text.split('\n')) {
		line = line.trimmed();
		if (line.isEmpty() || line.startsWith('#')) {
			continue;
		} else if (line.startsWith(u"re:"_q)) {
			auto regex = QRegularExpression(
				line.mid(3).trimmed(),
				QRegularExpression::CaseInsensitiveOption);
			if (regex.isValid()) {
				result.push_back({ line, std::move(regex) });
			}
		} else {
			// Indicators may be written defanged in the list too.
			result.push_back({ Refang(line), std::nullopt });
		}
	}
	return result;
}

std::vector<Term> &Terms() {
	static auto result = ParseTerms(ReadWatchlistText());
	return result;
}

void SaveWatchlist(const QString &text) {
	QDir().mkpath(QFileInfo(WatchlistPath()).absolutePath());
	auto file = QFile(WatchlistPath());
	if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
		file.write(text.toUtf8());
	}
	Terms() = ParseTerms(text);
}

[[nodiscard]] QString FindMatch(const QString &text) {
	if (text.isEmpty()) {
		return QString();
	}
	const auto refanged = Refang(text);
	for (const auto &term : Terms()) {
		if (term.regex) {
			if (term.regex->match(refanged).hasMatch()) {
				return term.text;
			}
		} else if (refanged.contains(term.text, Qt::CaseInsensitive)) {
			return term.text;
		}
	}
	return QString();
}

void RecordHit(
		not_null<HistoryItem*> item,
		const QString &term) {
	const auto session = &item->history()->session();
	const auto path = HitsPath(session);
	QDir().mkpath(QFileInfo(path).absolutePath());
	auto file = QFile(path);
	if (file.open(QIODevice::WriteOnly | QIODevice::Append)) {
		const auto entry = QJsonObject{
			{ u"term"_q, term },
			{ u"chat"_q, item->history()->peer->name() },
			{ u"chat_id"_q, QString::number(item->history()->peer->id.value) },
			{ u"sender"_q, item->from()->name() },
			{ u"msg_id"_q, QString::number(item->id.bare) },
			{ u"date"_q, qint64(item->date()) },
			{ u"text"_q, item->originalText().text.left(500) },
		};
		file.write(SealLine(
			QJsonDocument(entry).toJson(QJsonDocument::Compact)));
		file.write("\n");
	}
}

void CheckScam(not_null<HistoryItem*> item) {
	if (!ScamDetectorEnabled() || !IsStranger(item)) {
		return;
	}
	const auto report = AnalyzeMessageText(
		item->originalText().text,
		true);
	if (!report.atLeast(Severity::Warning)) {
		return;
	}
	if (const auto window = Core::App().activeWindow()) {
		auto text = TextWithEntities{ u"\u26A0\uFE0F "_q };
		text.append(Ui::Text::Bold(u"Возможное мошенничество от "_q
			+ item->history()->peer->name()));
		text.append('\n').append(report.findings.front().text);
		auto config = Ui::Toast::Config();
		config.text = std::move(text);
		config.duration = 8 * crl::time(1000);
		window->uiShow()->showToast(std::move(config));
	}
}

void CheckItem(not_null<HistoryItem*> item) {
	CheckScam(item);
	CollectIocs(item);
	if (!Watchlist.value() || item->out() || Terms().empty()) {
		return;
	}
	auto text = item->originalText().text;
	if (const auto media = item->media()) {
		if (const auto document = media->document()) {
			text += '\n' + document->filename();
		}
	}
	const auto term = FindMatch(text);
	if (term.isEmpty()) {
		return;
	}
	RecordHit(item, term);
	if (const auto window = Core::App().activeWindow()) {
		auto text = TextWithEntities{ u"\U0001F514 Наблюдение: "_q };
		text.append(Ui::Text::Bold(term));
		text.append(u"\n"_q
			+ item->history()->peer->name()
			+ u": "_q
			+ item->originalText().text.left(80));
		auto config = Ui::Toast::Config();
		config.text = std::move(text);
		config.duration = 6 * crl::time(1000);
		window->uiShow()->showToast(std::move(config));
		// Draw attention like an incoming call would.
		QApplication::alert(window->widget(), 0);
		QApplication::beep();
	}
}

[[nodiscard]] QString BotApiId(not_null<PeerData*> peer) {
	const auto id = peer->id;
	if (peerIsUser(id)) {
		return QString::number(peerToUser(id).bare);
	} else if (peerIsChat(id)) {
		return '-' + QString::number(peerToChat(id).bare);
	}
	return u"-100"_q + QString::number(peerToChannel(id).bare);
}

[[nodiscard]] QJsonObject PeerJson(not_null<PeerData*> peer) {
	auto result = QJsonObject{
		{ u"id"_q, BotApiId(peer) },
		{ u"name"_q, peer->name() },
	};
	if (const auto username = peer->username(); !username.isEmpty()) {
		result.insert(u"username"_q, '@' + username);
	}
	return result;
}

[[nodiscard]] QString IsoDate(TimeId date) {
	return date
		? base::unixtime::parse(date).toUTC().toString(Qt::ISODate)
		: QString();
}

[[nodiscard]] QString Sha256(const QByteArray &bytes) {
	return QString::fromLatin1(QCryptographicHash::hash(
		bytes,
		QCryptographicHash::Sha256).toHex());
}

[[nodiscard]] QString HtmlEscape(const QString &text) {
	return text.toHtmlEscaped().replace('\n', u"<br>"_q);
}

struct Manifest {
	QStringList lines;

	void add(const QString &relative, const QByteArray &bytes) {
		lines.push_back(Sha256(bytes) + u"  "_q + relative);
	}
};

bool WriteFile(
		const QString &folder,
		const QString &relative,
		const QByteArray &bytes,
		Manifest &manifest) {
	const auto path = folder + '/' + relative;
	QDir().mkpath(QFileInfo(path).absolutePath());
	auto file = QFile(path);
	if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)
		|| file.write(bytes) != bytes.size()) {
		return false;
	}
	manifest.add(relative, bytes);
	return true;
}

[[nodiscard]] QString SafeFileName(QString name) {
	static const auto bad = QRegularExpression("[\\\\/:*?\"<>|\\x00-\\x1F]");
	name.replace(bad, u"_"_q);
	// Never keep a disguised extension in evidence copies.
	for (const auto ch : {
			0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
			0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F }) {
		name.remove(QChar(ch));
	}
	return name.left(120);
}

QString WriteEvidence(
		const QString &root,
		const std::vector<not_null<HistoryItem*>> &items) {
	const auto stamp = QDateTime::currentDateTimeUtc();
	const auto folder = root
		+ u"/SecGram_evidence_"_q
		+ stamp.toString(u"yyyyMMdd_HHmmss"_q);
	if (!QDir().mkpath(folder)) {
		return QString();
	}
	auto manifest = Manifest();
	auto messages = QJsonArray();
	auto rows = QString();
	for (const auto &item : items) {
		const auto peer = item->history()->peer;
		auto json = QJsonObject{
			{ u"chat"_q, PeerJson(peer) },
			{ u"message_id"_q, QString::number(item->id.bare) },
			{ u"date_utc"_q, IsoDate(item->date()) },
			{ u"sender"_q, PeerJson(item->from()) },
			{ u"outgoing"_q, item->out() },
			{ u"text"_q, item->originalText().text },
		};
		if (const auto edited = item->Get<HistoryMessageEdited>()) {
			json.insert(u"edit_date_utc"_q, IsoDate(edited->date));
		}
		if (const auto forwarded = item->Get<HistoryMessageForwarded>()) {
			auto origin = QJsonObject{
				{ u"date_utc"_q, IsoDate(forwarded->originalDate) },
			};
			if (forwarded->originalSender) {
				origin.insert(
					u"sender"_q,
					PeerJson(forwarded->originalSender));
			} else if (forwarded->originalHiddenSenderInfo) {
				origin.insert(
					u"hidden_name"_q,
					forwarded->originalHiddenSenderInfo->name);
			}
			json.insert(u"forwarded"_q, origin);
		}
		if (item->hasDirectLink()) {
			json.insert(
				u"link"_q,
				item->history()->session().api().exportDirectMessageLink(
					item,
					false));
		}
		const auto iocs = ExtractIocs(item->originalText().text);
		if (!iocs.empty()) {
			json.insert(
				u"indicators"_q,
				QJsonDocument::fromJson(FormatIocs(
					iocs,
					IocFormat::Json,
					false).toUtf8()).array());
		}
		auto mediaCell = QString();
		const auto prefix = QString::number(item->id.bare);
		if (const auto media = item->media()) {
			if (const auto document = media->document()) {
				auto info = QJsonObject{
					{ u"type"_q, u"document"_q },
					{ u"name"_q, document->filename() },
					{ u"mime"_q, document->mimeString() },
					{ u"size"_q, qint64(document->size) },
				};
				const auto path = document->filepath(true);
				auto file = QFile(path);
				if (!path.isEmpty() && file.open(QIODevice::ReadOnly)) {
					const auto bytes = file.readAll();
					const auto relative = u"media/"_q + prefix + '_'
						+ SafeFileName(document->filename()) + u".bin"_q;
					if (WriteFile(folder, relative, bytes, manifest)) {
						info.insert(u"saved_as"_q, relative);
						info.insert(u"sha256"_q, Sha256(bytes));
					}
				} else {
					info.insert(u"saved_as"_q, u"not downloaded"_q);
				}
				mediaCell = HtmlEscape(document->filename());
				json.insert(u"media"_q, info);
			} else if (const auto photo = media->photo()) {
				auto info = QJsonObject{ { u"type"_q, u"photo"_q } };
				const auto view = photo->activeMediaView();
				const auto image = view
					? view->image(Data::PhotoSize::Large)
					: nullptr;
				if (image) {
					auto bytes = QByteArray();
					auto buffer = QBuffer(&bytes);
					buffer.open(QIODevice::WriteOnly);
					image->original().save(&buffer, "PNG");
					const auto relative = u"media/"_q + prefix + u".png"_q;
					if (WriteFile(folder, relative, bytes, manifest)) {
						info.insert(u"saved_as"_q, relative);
						info.insert(u"sha256"_q, Sha256(bytes));
						mediaCell = u"<img src=\"%1\" width=\"240\">"_q
							.arg(relative);
					}
				} else {
					info.insert(u"saved_as"_q, u"not loaded"_q);
					mediaCell = u"[фото]"_q;
				}
				json.insert(u"media"_q, info);
			}
		}
		messages.push_back(json);
		rows += u"<tr><td>%1</td><td>%2<br><small>%3</small></td>"
			"<td>%4<br><small>id %5</small></td><td>%6</td><td>%7</td></tr>\n"_q
			.arg(
				prefix,
				HtmlEscape(IsoDate(item->date())),
				HtmlEscape(peer->name()),
				HtmlEscape(item->from()->name()),
				BotApiId(item->from()),
				HtmlEscape(item->originalText().text),
				mediaCell);
	}

	const auto meta = QJsonObject{
		{ u"tool"_q, u"SecGram"_q },
		{ u"exported_utc"_q, stamp.toString(Qt::ISODate) },
		{ u"host"_q, QSysInfo::machineHostName() },
		{ u"count"_q, int(items.size()) },
	};
	const auto document = QJsonObject{
		{ u"meta"_q, meta },
		{ u"messages"_q, messages },
	};
	WriteFile(
		folder,
		u"messages.json"_q,
		QJsonDocument(document).toJson(QJsonDocument::Indented),
		manifest);

	const auto html = u"<!doctype html><meta charset=\"utf-8\">"
		"<title>SecGram evidence</title><style>"
		"body{font-family:sans-serif;margin:24px}"
		"table{border-collapse:collapse;width:100%}"
		"td,th{border:1px solid #999;padding:6px;vertical-align:top}"
		"th{background:#eee}</style>"
		"<h1>Доказательства SecGram</h1>"
		"<p>Экспортировано (UTC): %1<br>Компьютер: %2<br>"
		"Сообщений: %3</p>"
		"<p>Целостность: SHA-256 каждого файла — в manifest.txt, "
		"SHA-256 самого manifest.txt — в manifest.sha256.</p>"
		"<table><tr><th>ID</th><th>Дата (UTC) / чат</th>"
		"<th>Отправитель</th><th>Текст</th><th>Медиа</th></tr>"
		"%4</table>"_q
		.arg(
			stamp.toString(Qt::ISODate),
			HtmlEscape(QSysInfo::machineHostName()),
			QString::number(items.size()),
			rows);
	WriteFile(folder, u"report.html"_q, html.toUtf8(), manifest);

	const auto manifestText = (manifest.lines.join('\n') + '\n').toUtf8();
	auto dummy = Manifest();
	WriteFile(folder, u"manifest.txt"_q, manifestText, dummy);
	WriteFile(
		folder,
		u"manifest.sha256"_q,
		(Sha256(manifestText) + u"  manifest.txt\n"_q).toUtf8(),
		dummy);
	AppendCustody(folder, int(items.size()), Sha256(manifestText));
	return folder;
}

[[nodiscard]] QString DomainsPath() {
	return cWorkingDir() + u"tdata/secgram/domains.txt"_q;
}

[[nodiscard]] QString ReadDomainsText() {
	auto file = QFile(DomainsPath());
	return file.open(QIODevice::ReadOnly)
		? QString::fromUtf8(file.readAll())
		: QString();
}

struct Domains {
	QStringList allowed;
	QStringList blocked;
};

[[nodiscard]] Domains ParseDomains(const QString &text) {
	auto result = Domains();
	for (auto line : text.split('\n')) {
		line = Refang(line.trimmed()).toLower();
		if (line.size() < 2 || line.startsWith('#')) {
			continue;
		}
		const auto domain = QUrl::fromUserInput(line.mid(1)).host();
		if (line.startsWith('+') && !domain.isEmpty()) {
			result.allowed.push_back(domain);
		} else if (line.startsWith('-') && !domain.isEmpty()) {
			result.blocked.push_back(domain);
		}
	}
	return result;
}

Domains &DomainsData() {
	static auto result = ParseDomains(ReadDomainsText());
	return result;
}

[[nodiscard]] bool HostMatches(const QString &host, const QStringList &list) {
	return std::any_of(list.begin(), list.end(), [&](const QString &d) {
		return host == d || host.endsWith('.' + d);
	});
}

} // namespace

const char kOptionWatchlist[] = "secgram-watchlist";

void ReloadIntelLists() {
	Terms() = ParseTerms(ReadWatchlistText());
	DomainsData() = ParseDomains(ReadDomainsText());
}

DomainList DomainListed(const QString &host) {
	const auto lower = host.toLower();
	if (lower.isEmpty()) {
		return DomainList::None;
	} else if (HostMatches(lower, DomainsData().blocked)) {
		return DomainList::Blocked;
	} else if (HostMatches(lower, DomainsData().allowed)) {
		return DomainList::Allowed;
	}
	return DomainList::None;
}

void DomainListsBox(not_null<Ui::GenericBox*> box) {
	box->setTitle(rpl::single(u"Свои списки доменов"_q));
	box->setWidth(st::boxWideWidth);
	box->addRow(object_ptr<Ui::FlatLabel>(
		box,
		u"По одному домену в строке. «+домен» — доверенный, ссылки "
			"открываются без проверки. «-домен» — запрещённый, ссылки "
			"всегда помечаются как критические. Поддомены учитываются."_q,
		st::boxDividerLabel));
	box->addSkip(st::boxLittleSkip);
	const auto field = box->addRow(object_ptr<Ui::InputField>(
		box,
		st::defaultInputField,
		Ui::InputField::Mode::MultiLine,
		rpl::single(u"+mycompany.uz\n-evil-phish.top"_q),
		ReadDomainsText()));
	box->addButton(tr::lng_settings_save(), [=] {
		const auto text = field->getLastText();
		QDir().mkpath(QFileInfo(DomainsPath()).absolutePath());
		auto file = QFile(DomainsPath());
		if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
			file.write(text.toUtf8());
		}
		DomainsData() = ParseDomains(text);
		box->closeBox();
	});
	box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });
}

void AttachSession(not_null<Main::Session*> session) {
	InstallGlobalGuards();
	session->data().newItemAdded(
	) | rpl::on_next([](not_null<HistoryItem*> item) {
		CheckItem(item);
	}, session->lifetime());
}

void WatchlistBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller) {
	const auto session = &controller->session();
	box->setTitle(rpl::single(u"Список наблюдения"_q));
	box->setWidth(st::boxWideWidth);

	box->addRow(object_ptr<Ui::FlatLabel>(
		box,
		u"По одному слову или индикатору в строке: домены, IP, кошельки, "
			"имена, ключевые слова. Можно в обезвреженном виде "
			"(evil[.]com). Регулярное выражение — с префиксом «re:». "
			"Строки с # — комментарии."_q,
		st::boxDividerLabel));
	box->addSkip(st::boxLittleSkip);
	const auto field = box->addRow(object_ptr<Ui::InputField>(
		box,
		st::defaultInputField,
		Ui::InputField::Mode::MultiLine,
		rpl::single(u"Например:\nmycompany.uz\n10.20.30.40\nre:пароль|parol"_q),
		ReadWatchlistText()));
	field->setMaxHeight(st::boxWideWidth);

	auto hits = QStringList();
	auto file = QFile(HitsPath(session));
	if (file.open(QIODevice::ReadOnly)) {
		while (!file.atEnd()) {
			const auto object = QJsonDocument::fromJson(
				OpenLine(file.readLine())).object();
			if (object.isEmpty()) {
				continue;
			}
			hits.push_front(u"%1  «%2»  %3 / %4: %5"_q.arg(
				base::unixtime::parse(TimeId(object.value(u"date"_q)
					.toInteger())).toString(u"yyyy-MM-dd HH:mm"_q),
				object.value(u"term"_q).toString(),
				object.value(u"chat"_q).toString(),
				object.value(u"sender"_q).toString(),
				object.value(u"text"_q).toString().left(100)));
		}
	}
	box->addSkip(st::boxLittleSkip);
	box->addRow(object_ptr<Ui::FlatLabel>(
		box,
		rpl::single(Ui::Text::Bold(hits.isEmpty()
			? u"Совпадений пока нет."_q
			: u"Последние совпадения:"_q)),
		st::boxLabel));
	if (!hits.isEmpty()) {
		const auto label = box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			hits.mid(0, kShownHits).join('\n'),
			st::boxDividerLabel));
		label->setSelectable(true);
	}

	box->addButton(tr::lng_settings_save(), [=] {
		SaveWatchlist(field->getLastText());
		box->closeBox();
		controller->showToast(u"Список наблюдения сохранён: %1 шт."_q.arg(
			Terms().size()));
	});
	box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });
}

void ExportEvidence(
		std::shared_ptr<Ui::Show> show,
		std::vector<not_null<HistoryItem*>> items) {
	if (items.empty()) {
		return;
	}
	const auto session = &items.front()->history()->session();
	auto ids = std::vector<FullMsgId>();
	for (const auto &item : items) {
		ids.push_back(item->fullId());
	}
	const auto weak = base::make_weak(session);
	FileDialog::GetFolder(
		nullptr,
		u"Папка для сохранения доказательств"_q,
		QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation),
		[=](QString &&root) {
			const auto strong = weak.get();
			if (!strong) {
				return;
			}
			auto resolved = std::vector<not_null<HistoryItem*>>();
			for (const auto &id : ids) {
				if (const auto item = strong->data().message(id)) {
					resolved.push_back(item);
				}
			}
			const auto folder = WriteEvidence(root, resolved);
			if (folder.isEmpty()) {
				show->showToast(u"Не удалось создать папку."_q);
				return;
			}
			show->showToast(u"Доказательства сохранены: "_q + folder);
			File::ShowInFolder(folder + u"/report.html"_q);
		});
}

} // namespace SecGram
