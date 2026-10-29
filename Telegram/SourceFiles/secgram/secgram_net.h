/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "secgram/secgram_analyzer.h"

// Explicit, user-requested network checks. They contact third parties
// from this computer, so they never run automatically.
namespace SecGram {

struct ServerCheck {
	Report report;
	QStringList details;
};

// RDAP (domain registration date, registrar) + TLS certificate of host:443.
void CheckServer(
	const QString &host,
	Fn<void(ServerCheck)> done);

// Public phishing / malware URL feeds (OpenPhish, Phishing Army), stored in
// tdata/secgram/feeds.txt and used by the link guard offline.
void UpdateThreatFeeds(Fn<void(int count, QString error)> done);
[[nodiscard]] QString ThreatFeedMatch(const QString &url); // Source name.
[[nodiscard]] QString ThreatFeedsInfo();

} // namespace SecGram
