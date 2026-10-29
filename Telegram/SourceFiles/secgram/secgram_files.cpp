/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "secgram/secgram_files.h"

#include <QtCore/QDateTime>
#include <QtCore/QRegularExpression>
#include <QtCore/QTimeZone>
#include <QtCore/QSet>

#include <zlib.h>

#include <algorithm>
#include <array>
#include <cmath>

namespace SecGram {
namespace {

constexpr auto kShownEntries = 40;
constexpr auto kShownItems = 12;

[[nodiscard]] quint32 U32(const QByteArray &b, qint64 at) {
	if (at < 0 || at + 4 > b.size()) {
		return 0;
	}
	const auto p = reinterpret_cast<const uchar*>(b.constData() + at);
	return quint32(p[0])
		| (quint32(p[1]) << 8)
		| (quint32(p[2]) << 16)
		| (quint32(p[3]) << 24);
}

[[nodiscard]] quint16 U16(const QByteArray &b, qint64 at) {
	if (at < 0 || at + 2 > b.size()) {
		return 0;
	}
	const auto p = reinterpret_cast<const uchar*>(b.constData() + at);
	return quint16(p[0] | (p[1] << 8));
}

[[nodiscard]] QString FormatBytes(qint64 size) {
	if (size >= 1024 * 1024) {
		return QString::number(size / (1024. * 1024.), 'f', 1)
			+ QStringLiteral(" МБ");
	} else if (size >= 1024) {
		return QString::number(size / 1024., 'f', 1)
			+ QStringLiteral(" КБ");
	}
	return QString::number(size) + QStringLiteral(" Б");
}

[[nodiscard]] QString JoinShown(const QStringList &list) {
	auto result = list.mid(0, kShownItems).join(QStringLiteral(", "));
	if (list.size() > kShownItems) {
		result += QStringLiteral(" … (+%1)").arg(list.size() - kShownItems);
	}
	return result;
}

// Android binary XML: only the string pool is needed for the analysis.
[[nodiscard]] QStringList AxmlStrings(const QByteArray &xml) {
	auto result = QStringList();
	if (U16(xml, 0) != 0x0003 || xml.size() < 36) {
		return result;
	}
	const auto pool = qint64(U16(xml, 2)); // Header size of the XML chunk.
	if (U16(xml, pool) != 0x0001) {
		return result;
	}
	const auto count = U32(xml, pool + 8);
	const auto flags = U32(xml, pool + 16);
	const auto stringsStart = pool + U32(xml, pool + 20);
	const auto utf8 = (flags & 0x100) != 0;
	const auto offsets = pool + U16(xml, pool + 2);
	for (auto i = quint32(0); i < count && i < 100000; ++i) {
		auto at = stringsStart + U32(xml, offsets + i * 4);
		if (at >= xml.size()) {
			break;
		}
		if (utf8) {
			// UTF-16 length then UTF-8 length, each 1 or 2 bytes.
			auto skip = (uchar(xml[at]) & 0x80) ? 2 : 1;
			at += skip;
			if (at >= xml.size()) {
				break;
			}
			auto length = qint64(uchar(xml[at]));
			if (length & 0x80) {
				length = ((length & 0x7F) << 8) | uchar(xml[at + 1]);
				at += 2;
			} else {
				at += 1;
			}
			result.push_back(QString::fromUtf8(xml.mid(at, length)));
		} else {
			auto length = qint64(U16(xml, at));
			if (length & 0x8000) {
				length = ((length & 0x7FFF) << 16) | U16(xml, at + 2);
				at += 4;
			} else {
				at += 2;
			}
			if (at + length * 2 > xml.size()) {
				break;
			}
			result.push_back(QString::fromUtf16(
				reinterpret_cast<const char16_t*>(xml.constData() + at),
				length));
		}
	}
	return result;
}

struct Permission {
	const char *name;
	Severity severity;
	const char *meaning;
};

[[nodiscard]] const std::vector<Permission> &DangerousPermissions() {
	static const auto result = std::vector<Permission>{
		{ "RECEIVE_SMS", Severity::High,
			"получать SMS — перехват банковских кодов" },
		{ "READ_SMS", Severity::High,
			"читать SMS — кража кодов подтверждения" },
		{ "SEND_SMS", Severity::High,
			"отправлять SMS — платные подписки, распространение" },
		{ "BIND_ACCESSIBILITY_SERVICE", Severity::High,
			"служба спец. возможностей — полный контроль экрана" },
		{ "BIND_DEVICE_ADMIN", Severity::High,
			"права администратора — защита от удаления" },
		{ "SYSTEM_ALERT_WINDOW", Severity::Warning,
			"окна поверх других — поддельные формы входа в банк" },
		{ "BIND_NOTIFICATION_LISTENER_SERVICE", Severity::Warning,
			"читать все уведомления — включая коды" },
		{ "REQUEST_INSTALL_PACKAGES", Severity::Warning,
			"устанавливать другие приложения — дроппер" },
		{ "READ_CALL_LOG", Severity::Notice, "читать журнал звонков" },
		{ "CALL_PHONE", Severity::Notice, "совершать звонки" },
		{ "READ_CONTACTS", Severity::Notice, "читать контакты" },
		{ "RECORD_AUDIO", Severity::Notice, "записывать звук" },
		{ "CAMERA", Severity::Notice, "камера" },
		{ "ACCESS_FINE_LOCATION", Severity::Notice, "точное местоположение" },
		{ "QUERY_ALL_PACKAGES", Severity::Notice,
			"видеть все установленные приложения (поиск банков)" },
		{ "READ_PHONE_STATE", Severity::Notice, "данные SIM и телефона" },
		{ "RECEIVE_BOOT_COMPLETED", Severity::Info, "автозапуск" },
	};
	return result;
}

[[nodiscard]] const QStringList &PackerLibraries() {
	static const auto result = QStringList{
		"libjiagu", "libsecexe", "libsecmain", "libprotectclass",
		"libexec.so", "libexecmain", "libDexHelper", "libapkprotect",
		"libnqshield", "libtup.so", "libshell", "libmobisec",
	};
	return result;
}

[[nodiscard]] double Entropy(const QByteArray &data) {
	if (data.isEmpty()) {
		return 0.;
	}
	auto counts = std::array<qint64, 256>{};
	for (const auto ch : data) {
		++counts[uchar(ch)];
	}
	auto result = 0.;
	for (const auto count : counts) {
		if (count) {
			const auto p = double(count) / data.size();
			result -= p * std::log2(p);
		}
	}
	return result;
}

// MS-OVBA compressed container decompression ([MS-OVBA] 2.4.1).
[[nodiscard]] QByteArray DecompressOvba(
		const QByteArray &data,
		qint64 start,
		qint64 limit) {
	auto out = QByteArray();
	if (start >= data.size() || data[start] != 0x01) {
		return out;
	}
	auto pos = start + 1;
	while (pos + 2 <= data.size() && out.size() < limit) {
		const auto header = U16(data, pos);
		if (((header >> 12) & 7) != 3) {
			break;
		}
		const auto chunkEnd = std::min(
			qint64(data.size()),
			pos + (header & 0x0FFF) + 3);
		pos += 2;
		const auto chunkStart = out.size();
		if (!(header & 0x8000)) {
			out.append(data.mid(pos, 4096));
			pos += 4096;
			continue;
		}
		while (pos < chunkEnd) {
			const auto flags = uchar(data[pos++]);
			for (auto bit = 0; bit != 8 && pos < chunkEnd; ++bit) {
				if (!((flags >> bit) & 1)) {
					out.append(data[pos++]);
					continue;
				}
				if (pos + 2 > chunkEnd) {
					return out;
				}
				const auto token = U16(data, pos);
				pos += 2;
				const auto difference = out.size() - chunkStart;
				auto bitCount = 4;
				while ((1 << bitCount) < difference && bitCount < 12) {
					++bitCount;
				}
				const auto lengthMask = quint16(0xFFFF >> bitCount);
				const auto length = (token & lengthMask) + 3;
				const auto offset = ((token & ~lengthMask & 0xFFFF)
					>> (16 - bitCount)) + 1;
				const auto source = out.size() - offset;
				if (source < 0) {
					return out;
				}
				for (auto i = 0; i != length; ++i) {
					out.append(out[source + i]);
				}
			}
		}
	}
	return out;
}

// Binary parts of OOXML documents (macros are analyzed separately).
[[nodiscard]] bool OfficeInternal(const QString &name) {
	return name.endsWith(QStringLiteral(".bin"))
		&& (name.startsWith(QStringLiteral("word/"))
			|| name.startsWith(QStringLiteral("xl/"))
			|| name.startsWith(QStringLiteral("ppt/")));
}

} // namespace

ContainerReport AnalyzeMacros(const QByteArray &data) {
	auto result = ContainerReport();
	auto sources = QStringList();
	constexpr auto kMaxAttempts = 20000;
	auto attempts = 0;
	for (auto i = qint64(0); i + 3 < data.size(); ++i) {
		if (data[i] != 0x01 || ((U16(data, i + 1) >> 12) & 7) != 3) {
			continue;
		} else if (++attempts > kMaxAttempts) {
			break;
		}
		const auto code = DecompressOvba(data, i, 1024 * 1024);
		if (code.contains("Attribute VB_")) {
			sources.push_back(QString::fromLatin1(code));
			i += 16; // Skip this container start.
		}
	}
	if (sources.isEmpty()) {
		if (data.contains("VBA") || data.contains("_VBA_PROJECT")) {
			result.add(
				Severity::High,
				QStringLiteral("Есть проект VBA (макросы), исходный код "
					"извлечь не удалось."));
		}
		return result;
	}
	struct Keyword {
		const char *word;
		Severity severity;
		const char *meaning;
	};
	static const auto keywords = std::vector<Keyword>{
		{ "AutoOpen", Severity::High, "запуск при открытии" },
		{ "Auto_Open", Severity::High, "запуск при открытии" },
		{ "Document_Open", Severity::High, "запуск при открытии" },
		{ "Workbook_Open", Severity::High, "запуск при открытии" },
		{ "AutoExec", Severity::High, "автозапуск" },
		{ "Shell", Severity::High, "запуск команд" },
		{ "WScript.Shell", Severity::Critical, "запуск команд" },
		{ "powershell", Severity::Critical, "PowerShell" },
		{ "cmd.exe", Severity::Critical, "командная строка" },
		{ "URLDownloadToFile", Severity::Critical, "скачивание файла" },
		{ "XMLHTTP", Severity::High, "сетевые запросы" },
		{ "ADODB.Stream", Severity::High, "запись файлов" },
		{ "SaveToFile", Severity::High, "запись файлов" },
		{ "CreateObject", Severity::Warning, "создание COM-объектов" },
		{ "GetObject", Severity::Warning, "доступ к COM/WMI" },
		{ "Environ", Severity::Notice, "переменные окружения" },
		{ "StrReverse", Severity::Warning, "обфускация" },
		{ "Chr(", Severity::Notice, "сборка строк по кодам" },
		{ "CallByName", Severity::Warning, "скрытый вызов" },
		{ "VirtualAlloc", Severity::Critical, "внедрение шелл-кода" },
		{ "RtlMoveMemory", Severity::Critical, "внедрение шелл-кода" },
		{ "Lib \"kernel32", Severity::High, "вызов WinAPI" },
		{ "regsvr32", Severity::Critical, "запуск DLL" },
		{ "mshta", Severity::Critical, "запуск HTA" },
		{ "certutil", Severity::Critical, "скачивание/декодирование" },
	};
	const auto code = sources.join('\n');
	auto found = QStringList();
	auto severity = Severity::Info;
	for (const auto &keyword : keywords) {
		if (code.contains(QString::fromLatin1(keyword.word), Qt::CaseInsensitive)) {
			found.push_back(QStringLiteral("%1 (%2)").arg(
				QString::fromLatin1(keyword.word),
				QString::fromUtf8(keyword.meaning)));
			severity = std::max(severity, keyword.severity);
		}
	}
	result.add(
		std::max(severity, Severity::High),
		QStringLiteral("Макросы VBA: %1 модул(ей). Подозрительное: %2").arg(
			QString::number(sources.size()),
			found.isEmpty() ? QStringLiteral("—") : found.join(", ")));
	const auto iocs = ExtractIocs(code);
	if (!iocs.empty()) {
		result.add(
			Severity::High,
			QStringLiteral("Адреса/индикаторы в коде макроса: %1").arg(
				Defang(iocs.front().value)
					+ (iocs.size() > 1
						? QStringLiteral(" (+%1)").arg(iocs.size() - 1)
						: QString())));
	}
	auto lines = QStringList();
	for (const auto &line : code.split('\n')) {
		const auto trimmed = line.trimmed();
		if (trimmed.isEmpty() || trimmed.startsWith("Attribute ")) {
			continue;
		}
		lines.push_back(trimmed.left(160));
		if (lines.size() >= 25) {
			break;
		}
	}
	result.summary = QStringLiteral("Начало кода макроса:\n")
		+ lines.join('\n');
	return result;
}

ContainerReport AnalyzePe(const QByteArray &bytes) {
	auto result = ContainerReport();
	const auto pe = qint64(U32(bytes, 0x3C));
	if (U32(bytes, pe) != 0x00004550) {
		result.add(Severity::Notice, QStringLiteral("Повреждённый PE."));
		return result;
	}
	const auto machine = U16(bytes, pe + 4);
	const auto sections = U16(bytes, pe + 6);
	const auto timestamp = U32(bytes, pe + 8);
	const auto optionalSize = U16(bytes, pe + 20);
	const auto characteristics = U16(bytes, pe + 22);
	const auto optional = pe + 24;
	const auto magic = U16(bytes, optional);
	const auto pe32plus = (magic == 0x20b);
	const auto directories = optional + (pe32plus ? 112 : 96);
	const auto directory = [&](int index) {
		return std::make_pair(
			U32(bytes, directories + index * 8),
			U32(bytes, directories + index * 8 + 4));
	};
	const auto signature = directory(4);
	const auto clr = directory(14);
	const auto dll = (characteristics & 0x2000) != 0;

	auto details = QStringList();
	details.push_back(QStringLiteral("Тип: %1, %2%3").arg(
		dll ? QStringLiteral("DLL") : QStringLiteral("EXE"),
		machine == 0x8664
			? QStringLiteral("x64")
			: machine == 0x14c
			? QStringLiteral("x86")
			: machine == 0xaa64
			? QStringLiteral("ARM64")
			: QStringLiteral("0x%1").arg(machine, 0, 16),
		clr.second ? QStringLiteral(", .NET") : QString()));
	const auto compiled = QDateTime::fromSecsSinceEpoch(
		timestamp,
		QTimeZone::UTC);
	details.push_back(QStringLiteral("Дата компиляции: %1").arg(
		compiled.toString(QStringLiteral("yyyy-MM-dd HH:mm"))));
	if (compiled > QDateTime::currentDateTimeUtc().addDays(1)) {
		result.add(
			Severity::Warning,
			QStringLiteral("Дата компиляции в будущем — подделана."));
	}
	if (!signature.second) {
		result.add(
			Severity::Warning,
			QStringLiteral("Нет цифровой подписи (Authenticode)."));
	} else {
		details.push_back(QStringLiteral("Есть цифровая подпись "
			"(не проверялась)."));
	}

	static const auto packers = QStringList{
		"UPX", ".aspack", ".adata", "Themida", ".themida", ".vmp",
		"MPRESS", ".petite", ".nsp", "PEC2", ".enigma", ".boom",
	};
	auto table = optional + optionalSize;
	auto high = QStringList();
	auto found = QStringList();
	for (auto i = 0; i != sections && i < 96; ++i, table += 40) {
		const auto name = QString::fromLatin1(
			bytes.mid(table, 8)).remove(QChar(0));
		const auto rawSize = U32(bytes, table + 16);
		const auto rawOffset = U32(bytes, table + 20);
		const auto entropy = Entropy(bytes.mid(rawOffset, rawSize));
		if (entropy > 7.2 && rawSize > 1024) {
			high.push_back(QStringLiteral("%1 (%2)").arg(
				name,
				QString::number(entropy, 'f', 2)));
		}
		for (const auto &packer : packers) {
			if (name.contains(packer, Qt::CaseInsensitive)) {
				found.push_back(name);
			}
		}
	}
	if (!found.isEmpty()) {
		result.add(
			Severity::High,
			QStringLiteral("Упакован/защищён: %1 — код скрыт от анализа.")
				.arg(found.join(", ")));
	}
	if (!high.isEmpty()) {
		result.add(
			Severity::Warning,
			QStringLiteral("Секции с высокой энтропией (шифрованные или "
				"сжатые данные): %1").arg(high.join(", ")));
	}

	struct Api {
		const char *name;
		const char *meaning;
	};
	static const auto apis = std::vector<Api>{
		{ "CreateRemoteThread", "внедрение в процессы" },
		{ "WriteProcessMemory", "внедрение в процессы" },
		{ "VirtualAllocEx", "внедрение в процессы" },
		{ "NtUnmapViewOfSection", "process hollowing" },
		{ "SetWindowsHookEx", "перехват клавиатуры" },
		{ "GetAsyncKeyState", "кейлоггер" },
		{ "URLDownloadToFile", "скачивание файлов" },
		{ "InternetOpenUrl", "сетевые запросы" },
		{ "WinHttpOpen", "сетевые запросы" },
		{ "CryptEncrypt", "шифрование (шифровальщик?)" },
		{ "BCryptEncrypt", "шифрование (шифровальщик?)" },
		{ "IsDebuggerPresent", "антиотладка" },
		{ "AdjustTokenPrivileges", "повышение привилегий" },
		{ "RegSetValueEx", "запись в реестр (автозапуск)" },
		{ "CreateService", "установка службы" },
		{ "ShellExecute", "запуск программ" },
		{ "WinExec", "запуск программ" },
		{ "OpenClipboard", "доступ к буферу обмена" },
		{ "CryptUnprotectData", "кража паролей браузеров" },
		{ "vssadmin", "удаление теневых копий" },
	};
	auto suspicious = QStringList();
	for (const auto &api : apis) {
		if (bytes.contains(api.name)) {
			suspicious.push_back(QStringLiteral("%1 (%2)").arg(
				QString::fromLatin1(api.name),
				QString::fromUtf8(api.meaning)));
		}
	}
	if (suspicious.size() >= 3) {
		result.add(
			Severity::High,
			QStringLiteral("Подозрительные функции: %1").arg(
				JoinShown(suspicious)));
	} else if (!suspicious.isEmpty()) {
		result.add(
			Severity::Notice,
			QStringLiteral("Функции: %1").arg(suspicious.join(", ")));
	}
	const auto iocs = ExtractIocs(QString::fromLatin1(bytes.left(
		16 * 1024 * 1024)));
	auto network = QStringList();
	for (const auto &ioc : iocs) {
		if ((ioc.type == IocType::Url || ioc.type == IocType::IPv4)
			&& network.size() < kShownItems) {
			network.push_back(Defang(ioc.value));
		}
	}
	if (!network.isEmpty()) {
		result.add(
			Severity::Warning,
			QStringLiteral("Сетевые адреса в файле: %1").arg(
				network.join(", ")));
	}
	result.summary = details.join('\n');
	return result;
}

std::vector<ZipEntry> ListZip(const QByteArray &bytes, bool *ok) {
	auto result = std::vector<ZipEntry>();
	if (ok) {
		*ok = false;
	}
	// End of central directory, may be followed by a comment.
	const auto from = std::max(qint64(0), qint64(bytes.size()) - 65557);
	auto eocd = qint64(-1);
	for (auto i = qint64(bytes.size()) - 22; i >= from; --i) {
		if (U32(bytes, i) == 0x06054b50) {
			eocd = i;
			break;
		}
	}
	if (eocd < 0) {
		return result;
	}
	const auto count = U16(bytes, eocd + 10);
	auto at = qint64(U32(bytes, eocd + 16));
	for (auto i = 0; i != count; ++i) {
		if (U32(bytes, at) != 0x02014b50) {
			break;
		}
		const auto flags = U16(bytes, at + 8);
		const auto nameLength = U16(bytes, at + 28);
		const auto extraLength = U16(bytes, at + 30);
		const auto commentLength = U16(bytes, at + 32);
		auto entry = ZipEntry{
			.name = QString::fromUtf8(bytes.mid(at + 46, nameLength)),
			.size = qint64(U32(bytes, at + 24)),
			.compressedSize = qint64(U32(bytes, at + 20)),
			.offset = qint64(U32(bytes, at + 42)),
			.method = U16(bytes, at + 10),
			.encrypted = (flags & 1) != 0,
		};
		result.push_back(std::move(entry));
		at += 46 + nameLength + extraLength + commentLength;
	}
	if (ok) {
		*ok = true;
	}
	return result;
}

QByteArray ReadZipEntry(
		const QByteArray &bytes,
		const ZipEntry &entry,
		qint64 sizeLimit) {
	if (entry.encrypted
		|| entry.size > sizeLimit
		|| U32(bytes, entry.offset) != 0x04034b50) {
		return QByteArray();
	}
	const auto start = entry.offset
		+ 30
		+ U16(bytes, entry.offset + 26)
		+ U16(bytes, entry.offset + 28);
	const auto data = bytes.mid(start, entry.compressedSize);
	if (entry.method == 0) {
		return data;
	} else if (entry.method != 8) {
		return QByteArray();
	}
	auto result = QByteArray(entry.size, Qt::Uninitialized);
	auto stream = z_stream();
	stream.next_in = reinterpret_cast<Bytef*>(
		const_cast<char*>(data.constData()));
	stream.avail_in = uInt(data.size());
	stream.next_out = reinterpret_cast<Bytef*>(result.data());
	stream.avail_out = uInt(result.size());
	if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) {
		return QByteArray();
	}
	const auto status = inflate(&stream, Z_FINISH);
	inflateEnd(&stream);
	if (status != Z_STREAM_END) {
		return QByteArray();
	}
	result.resize(stream.total_out);
	return result;
}

ContainerReport AnalyzeZip(const QByteArray &bytes) {
	auto result = ContainerReport();
	auto ok = false;
	const auto entries = ListZip(bytes, &ok);
	if (!ok) {
		result.add(
			Severity::Notice,
			QStringLiteral("Не удалось прочитать оглавление архива "
				"(повреждён или ZIP64)."));
		return result;
	}
	auto executables = QStringList();
	auto disguised = QStringList();
	auto nested = QStringList();
	auto traversal = QStringList();
	auto encrypted = 0;
	auto total = qint64(0);
	auto lines = QStringList();
	for (const auto &entry : entries) {
		total += entry.size;
		if (entry.encrypted) {
			++encrypted;
		}
		if (entry.name.startsWith('/')
			|| entry.name.contains(QStringLiteral("../"))
			|| entry.name.contains(QStringLiteral("..\\"))) {
			traversal.push_back(entry.name);
		}
		if (entry.name.endsWith('/')) {
			continue;
		}
		const auto file = AnalyzeFileName(entry.name);
		if (file.atLeast(Severity::Critical)) {
			disguised.push_back(file.displayName);
		} else if (file.executable && !OfficeInternal(entry.name)) {
			executables.push_back(entry.name);
		} else if (file.realExtension == QStringLiteral("zip")
			|| file.realExtension == QStringLiteral("rar")
			|| file.realExtension == QStringLiteral("7z")
			|| file.realExtension == QStringLiteral("iso")
			|| file.realExtension == QStringLiteral("img")) {
			nested.push_back(entry.name);
		}
		if (lines.size() < kShownEntries) {
			lines.push_back(QStringLiteral("%1  (%2)%3").arg(
				entry.name,
				FormatBytes(entry.size),
				entry.encrypted ? QStringLiteral(" 🔒") : QString()));
		}
	}
	if (!disguised.isEmpty()) {
		result.add(
			Severity::Critical,
			QStringLiteral("Замаскированные файлы внутри: %1").arg(
				JoinShown(disguised)));
	}
	if (!executables.isEmpty()) {
		result.add(
			Severity::High,
			QStringLiteral("Исполняемые файлы внутри: %1").arg(
				JoinShown(executables)));
	}
	if (encrypted) {
		result.add(
			Severity::Warning,
			QStringLiteral("Файлов под паролем: %1. Антивирус не может "
				"проверить зашифрованное содержимое — частый приём "
				"доставки вредоносов.").arg(encrypted));
	}
	if (!traversal.isEmpty()) {
		result.add(
			Severity::High,
			QStringLiteral("Пути с выходом из папки (Zip Slip): %1").arg(
				JoinShown(traversal)));
	}
	if (!nested.isEmpty()) {
		result.add(
			Severity::Notice,
			QStringLiteral("Вложенные архивы / образы: %1").arg(
				JoinShown(nested)));
	}
	const auto packed = std::max(qint64(1), qint64(bytes.size()));
	if (total > 512 * 1024 * 1024 && total / packed > 100) {
		result.add(
			Severity::Warning,
			QStringLiteral("Распакованный размер %1 при архиве %2 — "
				"возможная ZIP-бомба.").arg(
				FormatBytes(total),
				FormatBytes(bytes.size())));
	}
	for (const auto &entry : entries) {
		if (entry.name.endsWith(QStringLiteral("vbaProject.bin"))) {
			const auto macros = AnalyzeMacros(ReadZipEntry(bytes, entry));
			for (const auto &finding : macros.findings) {
				result.findings.push_back(finding);
			}
			if (!macros.summary.isEmpty()) {
				lines.push_front(macros.summary + '\n');
			}
		}
	}
	result.summary = QStringLiteral("Файлов: %1, распакованный размер: %2\n")
		.arg(entries.size())
		.arg(FormatBytes(total))
		+ lines.join('\n')
		+ ((int(entries.size()) > kShownEntries)
			? QStringLiteral("\n…")
			: QString());
	return result;
}

ContainerReport AnalyzeApk(const QByteArray &bytes) {
	auto result = ContainerReport();
	auto ok = false;
	const auto entries = ListZip(bytes, &ok);
	if (!ok) {
		return AnalyzeZip(bytes);
	}
	auto dexCount = 0;
	auto hiddenCode = QStringList();
	auto abis = QSet<QString>();
	auto packers = QStringList();
	auto signedV1 = false;
	auto manifest = QByteArray();
	for (const auto &entry : entries) {
		const auto &name = entry.name;
		const auto lower = name.toLower();
		if (name == QStringLiteral("AndroidManifest.xml")) {
			manifest = ReadZipEntry(bytes, entry);
		} else if (!name.contains('/') && lower.endsWith(".dex")) {
			++dexCount;
		} else if ((lower.startsWith("assets/") || lower.startsWith("res/raw/"))
			&& (lower.endsWith(".dex") || lower.endsWith(".jar")
				|| lower.endsWith(".apk") || lower.endsWith(".so"))) {
			hiddenCode.push_back(name);
		} else if (lower.startsWith("lib/")) {
			const auto parts = name.split('/');
			if (parts.size() >= 3) {
				abis.insert(parts[1]);
			}
			for (const auto &packer : PackerLibraries()) {
				if (lower.contains(packer.toLower())) {
					packers.push_back(parts.back());
				}
			}
		} else if (lower.startsWith("meta-inf/")
			&& (lower.endsWith(".rsa") || lower.endsWith(".dsa")
				|| lower.endsWith(".ec"))) {
			signedV1 = true;
		}
	}

	const auto strings = AxmlStrings(manifest);
	auto permissions = QStringList();
	auto found = QSet<QString>();
	for (const auto &string : strings) {
		if (string.startsWith(QStringLiteral("android.permission."))) {
			const auto short_ = string.mid(19);
			if (!found.contains(short_)) {
				found.insert(short_);
				permissions.push_back(short_);
			}
		}
	}
	auto package = QString();
	static const auto packageRe = QRegularExpression(
		"^[a-z][a-z0-9_]*(\\.[a-z0-9_]+){1,}$");
	for (const auto &string : strings) {
		if (packageRe.match(string).hasMatch()
			&& !string.startsWith(QStringLiteral("android."))
			&& !string.startsWith(QStringLiteral("androidx."))
			&& !string.startsWith(QStringLiteral("com.google."))) {
			package = string;
			break;
		}
	}

	auto severest = std::vector<QString>();
	for (const auto &permission : DangerousPermissions()) {
		const auto name = QString::fromLatin1(permission.name);
		const auto has = found.contains(name)
			|| strings.contains(QStringLiteral("android.permission.") + name);
		if (has && permission.severity >= Severity::Notice) {
			result.add(
				permission.severity,
				QStringLiteral("%1: %2").arg(
					name,
					QString::fromUtf8(permission.meaning)));
		}
	}
	const auto sms = found.contains(QStringLiteral("RECEIVE_SMS"))
		|| found.contains(QStringLiteral("READ_SMS"));
	const auto control = found.contains(
			QStringLiteral("BIND_ACCESSIBILITY_SERVICE"))
		|| found.contains(QStringLiteral("SYSTEM_ALERT_WINDOW"))
		|| found.contains(
			QStringLiteral("BIND_NOTIFICATION_LISTENER_SERVICE"));
	if (sms && control) {
		result.add(
			Severity::Critical,
			QStringLiteral("Сочетание доступа к SMS и управления экраном / "
				"уведомлениями — типичный банковский троян. НЕ "
				"устанавливайте."));
	}
	if (strings.contains(QStringLiteral("android.provider.Telephony.SMS_RECEIVED"))) {
		result.add(
			Severity::High,
			QStringLiteral("Перехватывает входящие SMS (SMS_RECEIVED)."));
	}
	if (!hiddenCode.isEmpty()) {
		result.add(
			Severity::High,
			QStringLiteral("Скрытый код в ресурсах (загрузка во время "
				"работы): %1").arg(JoinShown(hiddenCode)));
	}
	if (!packers.isEmpty()) {
		result.add(
			Severity::Warning,
			QStringLiteral("Упакован протектором (%1) — содержимое "
				"скрыто от анализа.").arg(JoinShown(packers)));
	}
	if (!signedV1) {
		result.add(
			Severity::Info,
			QStringLiteral("Нет подписи v1 (META-INF) — может быть подписан "
				"только схемой v2/v3."));
	}
	if (manifest.isEmpty()) {
		result.add(
			Severity::Warning,
			QStringLiteral("Не удалось прочитать AndroidManifest.xml."));
	}
	result.summary = QStringLiteral("Пакет: %1\nDEX-файлов: %2\n"
		"Архитектуры: %3\nРазрешения (%4): %5").arg(
			package.isEmpty() ? QStringLiteral("?") : package,
			QString::number(dexCount),
			abis.isEmpty()
				? QStringLiteral("нет нативного кода")
				: QStringList(abis.begin(), abis.end()).join(", "),
			QString::number(permissions.size()),
			permissions.join(QStringLiteral(", ")));

	// Archive level problems too (disguised files etc).
	const auto zip = AnalyzeZip(bytes);
	for (const auto &finding : zip.findings) {
		if (finding.severity >= Severity::Warning
			&& !finding.text.contains(QStringLiteral("Исполняемые"))) {
			result.findings.push_back(finding);
		}
	}
	return result;
}

ContainerReport AnalyzePdf(const QByteArray &bytes) {
	auto result = ContainerReport();
	const auto count = [&](const char *key) {
		return int(bytes.count(QByteArray(key)));
	};
	const auto js = count("/JavaScript") + count("/JS");
	const auto openAction = count("/OpenAction");
	const auto aa = count("/AA");
	const auto launch = count("/Launch");
	const auto embedded = count("/EmbeddedFile");
	const auto xfa = count("/XFA");
	const auto acroForm = count("/AcroForm");
	const auto richMedia = count("/RichMedia");
	const auto objStm = count("/ObjStm");
	const auto encrypt = count("/Encrypt");
	const auto submit = count("/SubmitForm");
	const auto pages = int(bytes.count("/Type /Page"))
		+ int(bytes.count("/Type/Page"))
		- int(bytes.count("/Type /Pages"))
		- int(bytes.count("/Type/Pages"));

	if (js) {
		result.add(
			Severity::High,
			QStringLiteral("Содержит JavaScript (%1) — может выполнять код "
				"при открытии.").arg(js));
	}
	if (launch) {
		result.add(
			Severity::Critical,
			QStringLiteral("Действие /Launch — попытка запустить программу "
				"на компьютере."));
	}
	if (embedded) {
		result.add(
			Severity::High,
			QStringLiteral("Вложенные файлы (%1) — внутри может быть "
				"вредонос.").arg(embedded));
	}
	if (openAction || aa) {
		result.add(
			(js || launch) ? Severity::High : Severity::Notice,
			QStringLiteral("Автоматические действия при открытии "
				"(/OpenAction: %1, /AA: %2).").arg(openAction).arg(aa));
	}
	if (xfa || richMedia) {
		result.add(
			Severity::Warning,
			QStringLiteral("XFA-формы / RichMedia — частый вектор "
				"эксплойтов."));
	}
	if (submit) {
		result.add(
			Severity::Warning,
			QStringLiteral("Форма отправляет данные на сервер "
				"(/SubmitForm) — проверьте, куда."));
	}
	if (objStm) {
		result.add(
			Severity::Notice,
			QStringLiteral("Сжатые потоки объектов (/ObjStm): часть "
				"содержимого скрыта от этой проверки."));
	}
	if (encrypt) {
		result.add(
			Severity::Notice,
			QStringLiteral("Документ зашифрован."));
	}
	static const auto hexName = QRegularExpression(
		"/[A-Za-z]*#[0-9A-Fa-f]{2}[A-Za-z#0-9]*");
	if (hexName.match(QString::fromLatin1(bytes)).hasMatch()) {
		result.add(
			Severity::High,
			QStringLiteral("Имена объектов закодированы (#xx) — "
				"обфускация, чтобы скрыть /JavaScript и т.п."));
	}

	auto uris = QStringList();
	static const auto uriRe = QRegularExpression(
		"/URI\\s*\\(([^)]{4,500})\\)");
	auto i = uriRe.globalMatch(QString::fromLatin1(bytes));
	while (i.hasNext()) {
		const auto uri = i.next().captured(1);
		if (!uris.contains(uri)) {
			uris.push_back(uri);
		}
	}
	auto riskyLinks = 0;
	for (const auto &uri : uris) {
		if (AnalyzeUrl(uri).atLeast(Severity::High)) {
			++riskyLinks;
		}
	}
	if (riskyLinks) {
		result.add(
			Severity::High,
			QStringLiteral("Опасных ссылок в документе: %1.").arg(
				riskyLinks));
	}
	result.summary = QStringLiteral("Страниц: ~%1, форм: %2, ссылок: %3")
		.arg(std::max(pages, 0))
		.arg(acroForm)
		.arg(uris.size());
	if (!uris.isEmpty()) {
		result.summary += '\n' + uris.mid(0, kShownItems).join('\n');
	}
	return result;
}

ContainerReport AnalyzeContainer(const QByteArray &bytes) {
	if (bytes.startsWith("PK\x03\x04")) {
		auto ok = false;
		const auto entries = ListZip(bytes, &ok);
		const auto apk = ok && std::any_of(
			entries.begin(),
			entries.end(),
			[](const ZipEntry &entry) {
				return entry.name == QStringLiteral("AndroidManifest.xml");
			});
		return apk ? AnalyzeApk(bytes) : AnalyzeZip(bytes);
	} else if (bytes.startsWith("%PDF")) {
		return AnalyzePdf(bytes);
	} else if (bytes.startsWith("MZ")) {
		return AnalyzePe(bytes);
	} else if (bytes.startsWith("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")) {
		return AnalyzeMacros(bytes);
	}
	return ContainerReport();
}

} // namespace SecGram
