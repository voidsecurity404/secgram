/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

namespace Api {
struct MessageToSend;
} // namespace Api

namespace Data {
struct UnreviewedAuth;
} // namespace Data

namespace Main {
class Session;
} // namespace Main

namespace Ui {
class GenericBox;
} // namespace Ui

namespace Window {
class SessionController;
} // namespace Window

class HistoryItem;

// Account takeover protection.
namespace SecGram {

extern const char kOptionNewLoginAlert[];
extern const char kOptionLoginCodeGuard[];

// Shows a modal alert about a login from a new device.
// review(confirm) confirms it or terminates that session.
void NotifyNewAuthorization(
	const Data::UnreviewedAuth &auth,
	Fn<void(bool confirm)> review);

// Returns true when the text contains a recent Telegram login code.
[[nodiscard]] bool ContainsLoginCode(
	not_null<Main::Session*> session,
	const QString &text);

// Returns true if sending was taken over by a confirmation box,
// the box calls `send` again if the user insists.
[[nodiscard]] bool GuardLoginCodeSend(
	not_null<Main::Session*> session,
	const QString &text,
	Fn<void()> send);
[[nodiscard]] bool GuardLoginCodeForward(
	not_null<Main::Session*> session,
	const std::vector<not_null<HistoryItem*>> &items,
	Fn<void()> forward);

// Account security checklist.
void SecurityAuditBox(
	not_null<Ui::GenericBox*> box,
	not_null<Window::SessionController*> controller);

} // namespace SecGram
