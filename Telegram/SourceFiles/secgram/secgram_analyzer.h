/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QByteArray>

#include <vector>

// Pure analysis code: only QtCore is used here, so it can be unit-tested
// without the rest of the application.
namespace SecGram {

enum class Severity {
	Info,
	Notice,
	Warning,
	High,
	Critical,
};

[[nodiscard]] QString SeverityName(Severity severity);

struct Finding {
	Severity severity = Severity::Info;
	QString text;
};

struct Report {
	std::vector<Finding> findings;

	[[nodiscard]] Severity maxSeverity() const;
	[[nodiscard]] bool atLeast(Severity severity) const;
	void add(Severity severity, QString text);
};

// --- Links ---

struct UrlReport : Report {
	QString scheme;
	QString host; // As shown to the user (unicode).
	QString asciiHost; // Punycode form, what really gets resolved.
	QString registrableDomain;
	QString cleanUrl; // Without tracking parameters.
	QStringList trackingParams;
	QString redirectTarget; // Open redirect parameter value, if any.
};

[[nodiscard]] UrlReport AnalyzeUrl(const QString &url);

// Removes utm_*, fbclid, gclid and similar parameters.
[[nodiscard]] QString StripTracking(
	const QString &url,
	QStringList *removed = nullptr);

[[nodiscard]] QString RegistrableDomain(const QString &host);

// --- Indicators of compromise ---

enum class IocType {
	Url,
	Domain,
	IPv4,
	IPv6,
	Email,
	MD5,
	SHA1,
	SHA256,
	SHA512,
	CVE,
	MitreAttack,
	Bitcoin,
	Ethereum,
	Ton,
	TelegramUsername,
	RegistryKey,
	WindowsPath,
};

[[nodiscard]] QString IocTypeName(IocType type);

struct Ioc {
	IocType type = IocType::Url;
	QString value; // Refanged.

	friend inline bool operator==(const Ioc &a, const Ioc &b) {
		return (a.type == b.type) && (a.value == b.value);
	}
};

[[nodiscard]] std::vector<Ioc> ExtractIocs(const QString &text);

enum class IocFormat {
	Text,
	Csv,
	Json,
	Stix, // STIX 2.1 bundle of indicators.
	Misp, // MISP event JSON, importable in MISP.
	TheHive, // TheHive alert JSON with observables.
};

[[nodiscard]] QString FormatIocs(
	const std::vector<Ioc> &iocs,
	IocFormat format,
	bool defanged);

// hxxps://example[.]com, 10[.]0[.]0[.]1, user[@]mail[.]com
[[nodiscard]] QString Defang(const QString &indicator);
[[nodiscard]] QString Refang(const QString &text);
// Defangs every indicator found inside a free text.
[[nodiscard]] QString DefangText(const QString &text);

// --- Files ---

struct FileReport : Report {
	QString displayName; // Bidi controls made visible.
	QString realExtension;
	bool executable = false;
};

[[nodiscard]] FileReport AnalyzeFileName(
	const QString &name,
	const QString &mime = QString());

struct FileHashes {
	QString md5;
	QString sha1;
	QString sha256;
	qint64 size = 0;
	QString magicType; // Detected by content, empty if unknown.
	bool magicExecutable = false;
	bool ok = false;
};

// Blocking, call it off the main thread.
[[nodiscard]] FileHashes ComputeFileHashes(const QString &path);
[[nodiscard]] FileHashes ComputeBytesHashes(const QByteArray &bytes);

// Content based type detection by magic bytes.
[[nodiscard]] QString DetectMagicType(
	const QByteArray &head,
	bool *executable = nullptr);

// Adds content-vs-name mismatch findings to the report.
void ApplyContentCheck(FileReport &report, const FileHashes &hashes);

[[nodiscard]] QString VirusTotalHashUrl(const QString &sha256);

struct LookupLink {
	QString service;
	QString url;
};

// Web lookups of an indicator in public threat intelligence services.
// Opening them sends the indicator (never any file) to that service.
[[nodiscard]] std::vector<LookupLink> LookupLinks(const Ioc &ioc);

// --- People ---

struct PeerFacts {
	QString name;
	QString username;
	quint64 userId = 0; // Zero for chats and channels.
	bool verified = false;
	bool scam = false;
	bool fake = false;
	bool contact = false;
	bool bot = false;
};

// Impersonation red flags: "Telegram Support", mixed alphabets etc.
[[nodiscard]] Report AnalyzePeer(const PeerFacts &facts);

// --- Messages ---

// Social engineering patterns (Russian, Uzbek, English): prizes, free
// Premium, blocked cards, investments, urgency, fake jobs, airdrops.
[[nodiscard]] Report AnalyzeMessageText(
	const QString &text,
	bool fromStranger);

// --- Decoding ---

struct Decoded {
	QString kind; // "Base64", "Hex", "URL", "JWT", "Тип хеша"...
	QString value;
};

// Tries common encodings of an indicator / blob and identifies hashes.
[[nodiscard]] std::vector<Decoded> DecodeText(const QString &text);

// --- Metadata ---

// Removes EXIF (GPS, camera, serial numbers), XMP, IPTC and comments from
// JPEG and text / EXIF chunks from PNG. JPEG orientation is preserved.
// Returns the input unchanged if nothing was removed or format is unknown.
[[nodiscard]] QByteArray StripImageMetadata(
	const QByteArray &bytes,
	bool *changed = nullptr);

// MP4 / MOV: turns "udta" and "meta" boxes (GPS ©xyz, Apple location,
// device model) into "free" boxes of the same size, so no offsets move.
[[nodiscard]] QByteArray StripVideoMetadata(
	QByteArray bytes,
	bool *changed = nullptr);

} // namespace SecGram
