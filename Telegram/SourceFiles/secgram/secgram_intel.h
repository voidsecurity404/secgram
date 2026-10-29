/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

class HistoryItem;

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

// Watchlist alerts and evidence export.
namespace SecGram {

extern const char kOptionWatchlist[];

// Called once for every logged in session.
void AttachSession(not_null<Main::Session*> session);

enum class DomainList {
	None,
	Allowed,
	Blocked,
};
// Own allow / block lists, a domain matches its subdomains too.
[[nodiscard]] DomainList DomainListed(const QString &host);
void DomainListsBox(not_null<Ui::GenericBox*> box);

// Re-reads watchlist and domain lists after an import.
void ReloadIntelLists();

// Edit the watched terms and see the latest matches.
void WatchlistBox(
	not_null<Ui::GenericBox*> box,
	not_null<Window::SessionController*> controller);

// Asks for a folder and writes messages, media, hashes and a report.
void ExportEvidence(
	std::shared_ptr<Ui::Show> show,
	std::vector<not_null<HistoryItem*>> items);

} // namespace SecGram
