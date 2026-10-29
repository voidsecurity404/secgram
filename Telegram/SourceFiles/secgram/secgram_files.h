/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "secgram/secgram_analyzer.h"

// Static analysis of containers: ZIP (and APK / JAR / OOXML) and PDF.
// Only QtCore and zlib are used, so it is unit-testable.
namespace SecGram {

struct ZipEntry {
	QString name;
	qint64 size = 0;
	qint64 compressedSize = 0;
	qint64 offset = 0; // Local header offset.
	int method = 0;
	bool encrypted = false;
};

[[nodiscard]] std::vector<ZipEntry> ListZip(
	const QByteArray &bytes,
	bool *ok = nullptr);

// Extracts one stored or deflated entry, empty on failure.
[[nodiscard]] QByteArray ReadZipEntry(
	const QByteArray &bytes,
	const ZipEntry &entry,
	qint64 sizeLimit = 64 * 1024 * 1024);

struct ContainerReport : Report {
	QString summary; // Human readable details (entries, permissions...).
};

// Lists suspicious entries: executables, double extensions, encryption,
// path traversal, nested archives, zip bombs.
[[nodiscard]] ContainerReport AnalyzeZip(const QByteArray &bytes);

// Android application: permissions, receivers, native code, packers.
[[nodiscard]] ContainerReport AnalyzeApk(const QByteArray &bytes);

// pdfid-like keyword scan plus the list of embedded links.
[[nodiscard]] ContainerReport AnalyzePdf(const QByteArray &bytes);

// Windows executables: signature, packers, entropy, suspicious imports.
[[nodiscard]] ContainerReport AnalyzePe(const QByteArray &bytes);

// VBA macros (decompressed MS-OVBA source) in OLE or OOXML documents.
[[nodiscard]] ContainerReport AnalyzeMacros(const QByteArray &vbaContainer);

// Picks the right analysis by content, empty report for other types.
[[nodiscard]] ContainerReport AnalyzeContainer(const QByteArray &bytes);

} // namespace SecGram
