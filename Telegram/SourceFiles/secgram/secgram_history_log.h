/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

class History;
class HistoryItem;
class PeerData;

namespace Main {
class Session;
} // namespace Main

namespace Ui {
class GenericBox;
} // namespace Ui

// Local log of messages that other people deleted or edited.
// Stored as JSON lines in tdata/secgram/<user id>/history_log.jsonl.
namespace SecGram {

extern const char kOptionHistoryLog[];
extern const char kOptionKeepInChat[];

[[nodiscard]] bool HistoryLogEnabled();

void RecordDeleted(not_null<HistoryItem*> item);
void RecordEdited(
	not_null<HistoryItem*> item,
	const TextWithEntities &was,
	const TextWithEntities &now,
	TimeId editDate);

// Messages deleted by others stay in the chat marked "Удалено <time>".
// Removes such kept messages from `items`, the rest must be destroyed.
void KeepDeletedInChat(std::vector<not_null<HistoryItem*>> &items);

// After a restart: puts the logged deleted messages back between the
// loaded ones (by their original ids) and re-attaches edit history.
// `items` are the freshly created slice items sorted by id.
void RestoreInSlice(
	not_null<History*> history,
	std::vector<not_null<HistoryItem*>> &items);

// Text to show after an edit: the new text and below it all previous
// versions with the edit times. Only for messages of other people.
[[nodiscard]] TextWithEntities ShowEditInChat(
	not_null<HistoryItem*> item,
	const TextWithEntities &was,
	TextWithEntities now,
	TimeId editDate);

// Peer may be nullptr to show the log of all chats.
void HistoryLogBox(
	not_null<Ui::GenericBox*> box,
	not_null<Main::Session*> session,
	PeerData *peer,
	MsgId onlyMessage = 0);

[[nodiscard]] bool HasLoggedEdits(not_null<HistoryItem*> item);

} // namespace SecGram
