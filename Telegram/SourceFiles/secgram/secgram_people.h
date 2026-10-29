/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

class PeerData;

namespace Main {
class Session;
} // namespace Main

namespace Ui {
class GenericBox;
} // namespace Ui

// Local knowledge about people: name / username history and private notes.
// Stored in tdata/secgram/<user id>/people.json, never sent anywhere.
namespace SecGram {

extern const char kOptionNameHistory[];

void AttachPeopleTracking(not_null<Main::Session*> session);

struct NameChange {
	TimeId at = 0;
	QString name;
	QString username;
};
[[nodiscard]] std::vector<NameChange> NameHistory(not_null<PeerData*> peer);

[[nodiscard]] QString PeerNote(not_null<PeerData*> peer);
void SetPeerNote(not_null<PeerData*> peer, const QString &note);

void PeerNoteBox(not_null<Ui::GenericBox*> box, not_null<PeerData*> peer);

} // namespace SecGram
