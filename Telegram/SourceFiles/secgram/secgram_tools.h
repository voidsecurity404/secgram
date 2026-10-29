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
class Show;
} // namespace Ui

namespace Window {
class SessionController;
} // namespace Window

namespace SecGram {

// --- External scanners (used only if installed) ---

[[nodiscard]] bool ClamAvAvailable();
[[nodiscard]] bool YaraAvailable(); // yara binary and at least one rule.
[[nodiscard]] bool SandboxAvailable();
[[nodiscard]] QString YaraRulesFolder();

// done(output) with the scanner verdict text.
void ScanWithClamAv(const QString &path, Fn<void(QString)> done);
void ScanWithYara(const QString &path, Fn<void(QString)> done);

// Opens the file with xdg-open inside firejail without network access.
void OpenInSandbox(const QString &path);

// --- Per chat sets (stored per account) ---

[[nodiscard]] bool GhostReadChat(not_null<PeerData*> peer);
void SetGhostReadChat(not_null<PeerData*> peer, bool enabled);

[[nodiscard]] bool CollectIocsChat(not_null<PeerData*> peer);
void SetCollectIocsChat(not_null<PeerData*> peer, bool enabled);

// Appends indicators of a collected chat to ioc_feed.csv.
void CollectIocs(not_null<HistoryItem*> item);
[[nodiscard]] QString IocFeedPath(not_null<Main::Session*> session);

// --- Evidence ---

// Chain of custody: every export is appended to tdata/secgram/custody.log.
void AppendCustody(
	const QString &folder,
	int messages,
	const QString &manifestSha256);

// --- Team ---

// Watchlist, domain lists and templates in one JSON file.
void ExportTeamConfig(std::shared_ptr<Ui::Show> show);
void ImportTeamConfig(std::shared_ptr<Ui::Show> show);

// --- Productivity ---

void TemplatesBox(not_null<Ui::GenericBox*> box);

// Regex search over the loaded messages of a chat.
void RegexSearchBox(
	not_null<Ui::GenericBox*> box,
	not_null<Window::SessionController*> controller,
	not_null<History*> history);

} // namespace SecGram
