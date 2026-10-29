/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

namespace Window {
class SessionController;
} // namespace Window

// Updates from GitHub Releases of voidsecurity404/secgram.
//
// A self-contained install (tar.xz, portable folder) is replaced in
// place after the SHA-256 from SHA256SUMS.txt matches; a system package
// (.deb / .rpm) is downloaded and handed to the system installer.
namespace SecGram {

extern const char kOptionUpdateCheck[];

// The CI writes the release tag here.
inline constexpr auto kVersion = "1.0.2";

// Called once a session is ready, checks at most every 12 hours.
void CheckForUpdatesLater(not_null<Window::SessionController*> controller);

// From the settings: always checks and reports "up to date" too.
void CheckForUpdatesNow(not_null<Window::SessionController*> controller);

} // namespace SecGram
