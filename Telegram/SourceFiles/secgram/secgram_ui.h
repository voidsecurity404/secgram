/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "secgram/secgram_analyzer.h"

class HistoryItem;
class DocumentData;

namespace Ui {
class GenericBox;
class PopupMenu;
class Show;
} // namespace Ui

namespace Window {
class SessionController;
} // namespace Window

namespace style {
struct FlatLabel;
} // namespace style

namespace HistoryView {
struct ContextMenuRequest;
class ListWidget;
} // namespace HistoryView

namespace SecGram {

extern const char kOptionLinkGuard[];
extern const char kOptionConfirmAllLinks[];
extern const char kOptionStripTracking[];
extern const char kOptionFileGuard[];
extern const char kOptionContextTools[];
extern const char kOptionGhostRead[];
extern const char kOptionGhostTyping[];
extern const char kOptionGhostOnline[];
extern const char kOptionStripMetadata[];
extern const char kOptionScamDetector[];
extern const char kOptionBlockExecutables[];
extern const char kOptionNoRiskyAutoDownload[];
extern const char kOptionShowSeconds[];
extern const char kOptionConfirmRevoke[];
extern const char kOptionGhostStories[];
extern const char kOptionGhostMedia[];
extern const char kOptionHidePhone[];
extern const char kOptionPanic[];
extern const char kOptionClipboardGuard[];
extern const char kOptionNoLinkPreviews[];

[[nodiscard]] bool NoLinkPreviews();
void NotifyAddedToGroup(not_null<HistoryItem*> item);

[[nodiscard]] bool ShowSeconds();
[[nodiscard]] bool GhostStories();
[[nodiscard]] bool GhostMedia();
[[nodiscard]] QString MaskPhone(const QString &formatted);
void Panic();
// Panic hotkey and clipboard protection, installed once.
void InstallGlobalGuards();
[[nodiscard]] bool ConfirmRevoke();
[[nodiscard]] bool BlockAutoDownload(const QString &name, const QString &mime);

[[nodiscard]] bool LinkGuardEnabled();

// Ghost mode: don't reveal activity to other people.
[[nodiscard]] bool GhostRead();
[[nodiscard]] bool GhostTyping();
[[nodiscard]] bool GhostOnline();
[[nodiscard]] bool FileGuardEnabled();
[[nodiscard]] bool StripMetadataEnabled();
[[nodiscard]] bool ScamDetectorEnabled();

// Incoming message in a private chat with someone not in contacts.
[[nodiscard]] bool IsStranger(not_null<HistoryItem*> item);

// Called for every external link right before it is opened.
// May rewrite the url (tracking removal) and returns true if it took over
// the opening (showed a warning box).
[[nodiscard]] bool InterceptUrlOpen(QString &url, const QVariant &context);

// Adds the link analysis rows into an existing confirmation box.
void AddLinkFindings(
	not_null<Ui::GenericBox*> box,
	const UrlReport &report,
	const style::FlatLabel &st);

// Called before launching a downloaded file, returns true if it took over.
[[nodiscard]] bool InterceptFileLaunch(
	const QString &path,
	Fn<void()> launch);

struct LinkCheckArgs {
	QString url;
	Fn<void(QString)> open; // Nullptr when only inspecting.
	std::vector<Finding> extra; // Context findings (sender etc).
};
void LinkCheckBox(not_null<Ui::GenericBox*> box, LinkCheckArgs args);
[[nodiscard]] bool ParseIpLike(const QString &host);

// HEAD requests following Location headers, done(hops, error).
void ResolveRedirects(
	const QString &url,
	Fn<void(QStringList, QString)> done);

void IocBox(not_null<Ui::GenericBox*> box, QString text);
void MessageInfoBox(not_null<Ui::GenericBox*> box, not_null<HistoryItem*> item);
void FileCheckBox(
	not_null<Ui::GenericBox*> box,
	not_null<DocumentData*> document);

// Main SecGram panel with all the toggles, in Russian.
void SettingsBox(
	not_null<Ui::GenericBox*> box,
	not_null<Window::SessionController*> controller);

void DecodeBox(not_null<Ui::GenericBox*> box, QString text);

void FillMessageMenu(
	not_null<Ui::PopupMenu*> menu,
	not_null<HistoryView::ListWidget*> list,
	const HistoryView::ContextMenuRequest &request);

} // namespace SecGram
