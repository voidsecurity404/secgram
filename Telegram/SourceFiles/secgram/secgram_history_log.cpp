/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "secgram/secgram_history_log.h"

#include "secgram/secgram_crypto.h"

#include "base/options.h"
#include "base/unixtime.h"
#include "data/data_document.h"
#include "data/data_media_types.h"
#include "data/data_peer.h"
#include "history/history.h"
#include "history/history_item.h"
#include "history/history_item_components.h"
#include "history/history_item_helpers.h"
#include "history/history.h"
#include "core/application.h"
#include "data/data_session.h"
#include "window/window_controller.h"
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "settings.h"
#include "ui/layers/generic_box.h"
#include "ui/layers/show.h"
#include "ui/text/text_utilities.h"
#include "ui/widgets/labels.h"

#include "styles/style_layers.h"
#include "styles/style_widgets.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtGui/QClipboard>
#include <QtGui/QGuiApplication>

namespace SecGram {
namespace {

constexpr auto kMaxLogSize = qint64(16 * 1024 * 1024);
constexpr auto kShownLimit = 300;
constexpr auto kMaxCopiedMedia = qint64(200 * 1024 * 1024);

base::options::toggle KeepInChat({
	.id = kOptionKeepInChat,
	.name = "Показывать удалённые и изменённые в чате",
	.description = "Удалённые собеседником сообщения остаются в чате с "
		"пометкой «Удалено» и временем, а у изменённых видны прежние "
		"версии. Видно только вам. После перезапуска удалённые "
		"сообщения остаются в журнале.",
	.defaultValue = true,
});

base::options::toggle HistoryLog({
	.id = kOptionHistoryLog,
	.name = "Сохранять удалённые и изменённые сообщения",
	.description = "Сохранять локальную копию сообщений, которые удаляют "
		"другие, и прежний текст изменённых сообщений. Просмотр "
		"— из меню чата. Журнал шифруется AES-256-GCM, если включено "
		"«Шифровать журналы SecGram».",
});

[[nodiscard]] QString LogPath(not_null<Main::Session*> session) {
	return cWorkingDir()
		+ u"tdata/secgram/"_q
		+ QString::number(session->userId().bare)
		+ u"/history_log.jsonl"_q;
}

const auto kEditMarker = u"\n\n\u270F\uFE0F Изменено "_q;
const auto kDeletedMarker = u"\U0001F5D1 Удалено "_q;

[[nodiscard]] QString FullTime(TimeId time) {
	return base::unixtime::parse(time).toString(u"dd.MM.yyyy HH:mm:ss"_q);
}

struct LoggedEntry {
	bool deleted = false;
	PeerId chat = 0;
	MsgId id = 0;
	PeerId sender = 0;
	TimeId date = 0;
	TimeId at = 0;
	QString text;
	QString newText;
	QString file;
};

[[nodiscard]] LoggedEntry Parse(const QJsonObject &object) {
	const auto edited = object.value(u"kind"_q).toString() == u"edited"_q;
	return {
		.deleted = !edited,
		.chat = PeerId(object.value(u"chat_id"_q).toString().toULongLong()),
		.id = MsgId(object.value(u"msg_id"_q).toString().toLongLong()),
		.sender = PeerId(
			object.value(u"sender_id"_q).toString().toULongLong()),
		.date = TimeId(object.value(u"date"_q).toInteger()),
		.at = TimeId(edited
			? object.value(u"edit_date"_q).toInteger()
			: object.value(u"at"_q).toInteger()),
		.text = object.value(u"text"_q).toString(),
		.newText = object.value(u"new_text"_q).toString(),
		.file = object.value(u"file"_q).toString(),
	};
}

// Parsed (and decrypted) log, per log file, loaded on first use.
std::map<QString, std::vector<LoggedEntry>> &Cache() {
	static auto result = std::map<QString, std::vector<LoggedEntry>>();
	return result;
}

std::vector<LoggedEntry> &Entries(not_null<Main::Session*> session);

void Append(not_null<Main::Session*> session, const QJsonObject &entry) {
	Entries(session).push_back(Parse(entry));
	const auto path = LogPath(session);
	QDir().mkpath(QFileInfo(path).absolutePath());
	if (QFileInfo(path).size() > kMaxLogSize) {
		const auto old = path + u".1"_q;
		QFile::remove(old);
		QFile::rename(path, old);
	}
	auto file = QFile(path);
	if (file.open(QIODevice::WriteOnly | QIODevice::Append)) {
		file.write(SealLine(
			QJsonDocument(entry).toJson(QJsonDocument::Compact)));
		file.write("\n");
	}
}

[[nodiscard]] QJsonObject BaseEntry(not_null<HistoryItem*> item) {
	const auto peer = item->history()->peer;
	const auto from = item->from();
	auto result = QJsonObject{
		{ u"chat_id"_q, QString::number(peer->id.value) },
		{ u"chat"_q, peer->name() },
		{ u"sender_id"_q, QString::number(from->id.value) },
		{ u"sender"_q, from->name() },
		{ u"msg_id"_q, QString::number(item->id.bare) },
		{ u"date"_q, qint64(item->date()) },
		{ u"at"_q, qint64(base::unixtime::now()) },
	};
	if (const auto username = from->username(); !username.isEmpty()) {
		result.insert(u"sender_username"_q, username);
	}
	if (const auto media = item->media()) {
		if (const auto document = media->document()) {
			result.insert(u"file"_q, document->filename());
			result.insert(u"mime"_q, document->mimeString());
			const auto path = document->filepath(true);
			if (!path.isEmpty()) {
				result.insert(u"local_path"_q, path);
			}
		} else if (media->photo()) {
			result.insert(u"file"_q, u"[фото]"_q);
		}
	}
	return result;
}

[[nodiscard]] bool ShouldRecord(not_null<HistoryItem*> item) {
	return (HistoryLog.value() || KeepInChat.value())
		&& !item->out()
		&& !item->isLocal()
		&& item->isRegular();
}

[[nodiscard]] QString FormatTime(qint64 time) {
	return time
		? base::unixtime::parse(TimeId(time)).toString(
			u"yyyy-MM-dd HH:mm:ss"_q)
		: QString();
}

[[nodiscard]] TextWithEntities Slice(
		const TextWithEntities &text,
		int from,
		int till) {
	auto result = TextWithEntities{ text.text.mid(from, till - from) };
	for (const auto &entity : text.entities) {
		const auto start = std::max(entity.offset(), from);
		const auto finish = std::min(entity.offset() + entity.length(), till);
		if (finish > start) {
			result.entities.push_back(EntityInText(
				entity.type(),
				start - from,
				finish - start,
				entity.data()));
		}
	}
	return result;
}

// The server text and the previous versions SecGram appended to it.
struct SplitText {
	TextWithEntities base;
	TextWithEntities history;
};

[[nodiscard]] SplitText Split(const TextWithEntities &text) {
	const auto index = text.text.indexOf(kEditMarker);
	if (index < 0) {
		return { text, {} };
	}
	return {
		Slice(text, 0, index),
		Slice(text, index, text.text.size()),
	};
}


void AddDeletedNotice(not_null<History*> history, int count, bool own) {
	const auto now = base::unixtime::now();
	auto text = TextWithEntities{ (own
		? u"\U0001F5D1 Удалено ваших сообщений: %1 \u2014 %2"_q
		: history->peer->isUser()
		? u"\U0001F5D1 Собеседник удалил сообщений: %1 \u2014 %2"_q
		: u"\U0001F5D1 Удалено сообщений: %1 \u2014 %2"_q).arg(
			QString::number(count),
			FullTime(now)) };
	const auto item = history->makeMessage({
		.id = history->owner().nextLocalMessageId(),
		.flags = MessageFlag::Local,
		.date = now,
	}, PreparedServiceText{ std::move(text) });
	history->addNewLocalMessage(item);
}

std::vector<LoggedEntry> &Entries(not_null<Main::Session*> session) {
	const auto path = LogPath(session);
	const auto i = Cache().find(path);
	if (i != Cache().end()) {
		return i->second;
	}
	auto result = std::vector<LoggedEntry>();
	for (const auto &name : { path + u".1"_q, path }) {
		auto file = QFile(name);
		if (!file.open(QIODevice::ReadOnly)) {
			continue;
		}
		while (!file.atEnd()) {
			const auto object = QJsonDocument::fromJson(
				OpenLine(file.readLine())).object();
			if (!object.isEmpty()) {
				result.push_back(Parse(object));
			}
		}
	}
	return Cache().emplace(path, std::move(result)).first->second;
}

[[nodiscard]] TextWithEntities DeletedText(const LoggedEntry &entry) {
	auto result = Ui::Text::Bold(kDeletedMarker + FullTime(entry.at));
	result.append('\n').append(entry.text);
	if (!entry.file.isEmpty()) {
		result.append(u"\n\U0001F4CE "_q + entry.file);
	}
	return result;
}

} // namespace

const char kOptionHistoryLog[] = "secgram-history-log";
const char kOptionKeepInChat[] = "secgram-keep-in-chat";

void KeepDeletedInChat(std::vector<not_null<HistoryItem*>> &items) {
	if (!KeepInChat.value()) {
		return;
	}
	struct Counts {
		int others = 0;
		int own = 0;
	};
	auto perHistory = base::flat_map<not_null<History*>, Counts>();
	const auto now = base::unixtime::now();
	const auto keep = [&](not_null<HistoryItem*> item) {
		if (item->isService() || item->isLocal() || !item->isRegular()) {
			return false;
		}
		auto &counts = perHistory[item->history()];
		++(item->out() ? counts.own : counts.others);
		const auto &text = item->originalText();
		if (!text.text.startsWith(kDeletedMarker)) {
			auto marked = Ui::Text::Bold(kDeletedMarker + FullTime(now));
			marked.append('\n').append(text);
			item->setText(std::move(marked));
			item->history()->owner().requestItemResize(item);
		}
		return true;
	};
	items.erase(
		std::remove_if(items.begin(), items.end(), keep),
		items.end());
	for (const auto &[history, counts] : perHistory) {
		AddDeletedNotice(
			history,
			counts.others + counts.own,
			!counts.others);
		if (counts.others) {
			if (const auto window = Core::App().activeWindow()) {
				window->uiShow()->showToast(
					u"\U0001F5D1 %1: удалено сообщений — %2"_q.arg(
						history->peer->name(),
						QString::number(counts.others)));
			}
		}
	}
}

void RestoreInSlice(
		not_null<History*> history,
		std::vector<not_null<HistoryItem*>> &items) {
	if (!KeepInChat.value() || items.empty()) {
		return;
	}
	const auto peerId = history->peer->id;
	auto &entries = Entries(&history->session());
	auto min = items.front()->id;
	auto max = items.front()->id;
	for (const auto &item : items) {
		min = std::min(min, item->id);
		max = std::max(max, item->id);
	}
	// Deleted messages newer than everything left on the server can be
	// restored only together with the newest slice.
	const auto last = history->lastMessage();
	const auto newest = !last || (last->id <= max);

	auto restored = std::vector<not_null<HistoryItem*>>();
	auto seen = base::flat_set<MsgId>();
	for (auto i = entries.rbegin(); i != entries.rend(); ++i) {
		const auto &entry = *i;
		if (!entry.deleted
			|| entry.chat != peerId
			|| entry.id <= min
			|| (entry.id >= max && !newest)
			|| entry.id == max
			|| seen.contains(entry.id)
			|| history->owner().message(peerId, entry.id)) {
			continue;
		}
		seen.emplace(entry.id);
		auto flags = MessageFlags();
		if (entry.sender && entry.sender != peerId) {
			flags |= MessageFlag::HasFromId;
		}
		restored.push_back(history->makeMessage(
			HistoryItemCommonFields{
				.id = entry.id,
				.flags = flags,
				.from = entry.sender ? entry.sender : peerId,
				.date = entry.date,
			},
			DeletedText(entry),
			MTP_messageMediaEmpty()));
	}
	if (!restored.empty()) {
		items.insert(items.end(), restored.begin(), restored.end());
		ranges::sort(items, ranges::less(), &HistoryItem::id);
	}

	// Edit history of messages that are still there.
	for (const auto &item : items) {
		if (item->out()
			|| !item->Get<HistoryMessageEdited>()
			|| item->originalText().text.contains(kEditMarker)
			|| item->originalText().text.startsWith(kDeletedMarker)) {
			continue;
		}
		auto edits = std::vector<const LoggedEntry*>();
		for (const auto &entry : entries) {
			if (!entry.deleted
				&& entry.chat == peerId
				&& entry.id == item->id) {
				edits.push_back(&entry);
			}
		}
		if (edits.empty()) {
			continue;
		}
		ranges::sort(edits, ranges::greater(), &LoggedEntry::at);
		auto text = item->originalText();
		for (const auto edit : edits) {
			auto suffix = Ui::Text::Italic(
				kEditMarker + FullTime(edit->at) + u" \u00B7 было:\n"_q);
			auto quoted = TextWithEntities{ edit->text };
			if (!quoted.text.isEmpty()) {
				quoted.entities.push_back(EntityInText(
					EntityType::Blockquote,
					0,
					int(quoted.text.size())));
			}
			text.append(suffix).append(quoted);
		}
		item->setText(std::move(text));
	}
}

TextWithEntities ShowEditInChat(
		not_null<HistoryItem*> item,
		const TextWithEntities &was,
		TextWithEntities now,
		TimeId editDate) {
	if (!KeepInChat.value() || item->out() || item->isLocal()) {
		return now;
	}
	const auto [base, history] = Split(was);
	if (base.text == now.text || base.text.isEmpty()) {
		// Same text (views, reactions or a reload): keep the history.
		return history.text.isEmpty() ? now : now.append(history);
	}
	auto suffix = TextWithEntities{ kEditMarker };
	suffix.append(FullTime(editDate)).append(u" \u00B7 было:\n"_q);
	suffix = Ui::Text::Italic(suffix.text);
	auto quoted = base;
	if (!quoted.text.isEmpty()) {
		quoted.entities.push_back(EntityInText(
			EntityType::Blockquote,
			0,
			int(quoted.text.size())));
	}
	return now.append(suffix).append(quoted).append(history);
}

bool HistoryLogEnabled() {
	return HistoryLog.value();
}

void RecordDeleted(not_null<HistoryItem*> item) {
	if (!ShouldRecord(item)) {
		return;
	}
	auto entry = BaseEntry(item);
	entry.insert(u"kind"_q, u"deleted"_q);
	entry.insert(u"text"_q, item->originalText().text);
	// Keep a copy of the downloaded file, the original will be removed
	// from the cache together with the message sooner or later.
	const auto local = entry.value(u"local_path"_q).toString();
	if (!local.isEmpty() && QFileInfo(local).size() < kMaxCopiedMedia) {
		const auto folder = QFileInfo(LogPath(&item->history()->session()))
			.absolutePath() + u"/deleted_media/"_q;
		QDir().mkpath(folder);
		const auto copy = folder
			+ QString::number(item->id.bare)
			+ '_'
			+ QFileInfo(local).fileName();
		if (QFile::copy(local, copy)) {
			entry.insert(u"local_path"_q, copy);
		}
	}
	Append(&item->history()->session(), entry);
}

void RecordEdited(
		not_null<HistoryItem*> item,
		const TextWithEntities &was,
		const TextWithEntities &now,
		TimeId editDate) {
	const auto previous = Split(was).base;
	if (!ShouldRecord(item) || previous.text == now.text) {
		return;
	}
	auto entry = BaseEntry(item);
	entry.insert(u"kind"_q, u"edited"_q);
	entry.insert(u"text"_q, previous.text);
	entry.insert(u"new_text"_q, now.text);
	entry.insert(u"edit_date"_q, qint64(editDate));
	Append(&item->history()->session(), entry);
}

bool HasLoggedEdits(not_null<HistoryItem*> item) {
	if (!item->Get<HistoryMessageEdited>()) {
		return false;
	}
	auto file = QFile(LogPath(&item->history()->session()));
	if (!file.open(QIODevice::ReadOnly)) {
		return false;
	}
	const auto chat = QString::number(item->history()->peer->id.value);
	const auto id = QString::number(item->id.bare);
	while (!file.atEnd()) {
		const auto line = OpenLine(file.readLine());
		if (!line.contains("\"edited\"")) {
			continue;
		}
		const auto object = QJsonDocument::fromJson(line).object();
		if (object.value(u"chat_id"_q).toString() == chat
			&& object.value(u"msg_id"_q).toString() == id) {
			return true;
		}
	}
	return false;
}

void HistoryLogBox(
		not_null<Ui::GenericBox*> box,
		not_null<Main::Session*> session,
		PeerData *peer,
		MsgId onlyMessage) {
	box->setTitle(rpl::single(peer
		? (u"Удалённые и изменённые: "_q + peer->name())
		: u"Удалённые и изменённые сообщения"_q));
	box->setWidth(st::boxWideWidth);

	auto entries = std::vector<QJsonObject>();
	const auto filter = peer ? QString::number(peer->id.value) : QString();
	for (const auto &path : { LogPath(session) + u".1"_q, LogPath(session) }) {
		auto file = QFile(path);
		if (!file.open(QIODevice::ReadOnly)) {
			continue;
		}
		while (!file.atEnd()) {
			const auto object = QJsonDocument::fromJson(
				OpenLine(file.readLine())).object();
			if (!object.isEmpty()
				&& (filter.isEmpty()
					|| object.value(u"chat_id"_q).toString() == filter)
				&& (!onlyMessage
					|| object.value(u"msg_id"_q).toString()
						== QString::number(onlyMessage.bare))) {
				entries.push_back(object);
			}
		}
	}
	std::reverse(entries.begin(), entries.end());
	if (entries.size() > kShownLimit) {
		entries.resize(kShownLimit);
	}

	if (entries.empty()) {
		box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			HistoryLog.value()
				? u"Пока ничего не записано."_q
				: u"Запись выключена. Включите «Сохранять удалённые и "
					"изменённые сообщения» в меню «Безопасность SecGram»."_q,
			st::boxLabel));
	}
	auto plain = QString();
	for (const auto &entry : entries) {
		const auto kind = entry.value(u"kind"_q).toString();
		const auto deleted = (kind == u"deleted"_q);
		auto header = (deleted ? u"\U0001F5D1 Удалено"_q : u"✏ Изменено"_q)
			+ u"  •  "_q
			+ entry.value(u"sender"_q).toString();
		if (!peer) {
			header += u"в чате "_q + entry.value(u"chat"_q).toString();
		}
		auto details = u"отправлено %1, %2 %3, сообщение #%4"_q.arg(
			FormatTime(entry.value(u"date"_q).toInteger()),
			deleted ? u"удалено"_q : u"изменено"_q,
			FormatTime(deleted
				? entry.value(u"at"_q).toInteger()
				: entry.value(u"edit_date"_q).toInteger()),
			entry.value(u"msg_id"_q).toString());
		auto body = entry.value(u"text"_q).toString();
		if (const auto file = entry.value(u"file"_q).toString();
				!file.isEmpty()) {
			body += (body.isEmpty() ? u""_q : u"\n"_q)
				+ u"\U0001F4CE "_q + file;
			const auto local = entry.value(u"local_path"_q).toString();
			if (!local.isEmpty()) {
				body += u"  ("_q + local + ')';
			}
		}
		if (!deleted) {
			body = u"Было: "_q + body
				+ u"\nСтало: "_q + entry.value(u"new_text"_q).toString();
		}
		const auto label = box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			rpl::single(Ui::Text::Bold(header)
				.append('\n')
				.append(details)
				.append('\n')
				.append(body)),
			st::boxLabel));
		label->setSelectable(true);
		box->addSkip(st::boxLittleSkip);
		plain += header + '\n' + details + '\n' + body + u"\n\n"_q;
	}

	if (!entries.empty()) {
		box->addButton(rpl::single(u"Копировать всё"_q), [=] {
			QGuiApplication::clipboard()->setText(plain);
			box->uiShow()->showToast(u"Журнал скопирован"_q);
		});
	}
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
}

} // namespace SecGram
