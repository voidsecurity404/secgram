/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "secgram/secgram_analyzer.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QRegularExpression>
#include <QtCore/QSet>
#include <QtCore/QUrl>
#include <QtCore/QUrlQuery>
#include <QtCore/QUuid>
#include <QtCore/QDateTime>
#include <QtCore/QTimeZone>

#include <algorithm>
#include <array>
#include <cstring>
#include <optional>

namespace SecGram {
namespace {

using Set = QSet<QString>;

[[nodiscard]] Set MakeSet(const char *list) {
	const auto parts = QString::fromLatin1(list).split(
		' ',
		Qt::SkipEmptyParts);
	return Set(parts.begin(), parts.end());
}

[[nodiscard]] const Set &ExecutableExtensions() {
	static const auto result = MakeSet(
		// Windows.
		"exe com scr pif bat cmd msi msp mst cpl dll sys drv ocx hta js "
		"jse vbs vbe wsf wsh ws wsc ps1 psm1 psd1 ps1xml reg lnk url scf "
		"inf chm jar jnlp appref-ms application gadget msc hlp sct vb "
		"vbscript library-ms settingcontent-ms search-ms appx appxbundle "
		"msix msixbundle xll xbap iqy slk cab "
		// macOS.
		"app pkg mpkg dmg command terminal scpt scptd applescript "
		"workflow action "
		// Linux and scripts.
		"sh bash zsh csh ksh fish run bin deb rpm appimage flatpak snap "
		"desktop elf out pl py pyw pyz pyc rb php lua "
		// Mobile.
		"apk apks xapk apkm aab ipa");
	return result;
}

[[nodiscard]] const Set &MacroExtensions() {
	static const auto result = MakeSet(
		"docm dotm xlsm xltm xlam xlsb pptm potm ppam ppsm sldm");
	return result;
}

[[nodiscard]] const Set &ContainerExtensions() {
	static const auto result = MakeSet("iso img vhd vhdx udf");
	return result;
}

[[nodiscard]] const Set &ArchiveExtensions() {
	static const auto result = MakeSet(
		"zip rar 7z tar gz tgz bz2 xz zst arj ace lzh lha z cpio");
	return result;
}

[[nodiscard]] const Set &ActiveDocumentExtensions() {
	static const auto result = MakeSet(
		"html htm xhtml shtml mht mhtml svg svgz xml hta");
	return result;
}

[[nodiscard]] const Set &LegacyOfficeExtensions() {
	static const auto result = MakeSet("doc dot xls xlt ppt pps rtf one");
	return result;
}

[[nodiscard]] const Set &LureExtensions() {
	static const auto result = MakeSet(
		"pdf doc docx xls xlsx ppt pptx txt rtf jpg jpeg png gif bmp webp "
		"mp4 mov avi mkv mp3 wav ogg csv odt");
	return result;
}

[[nodiscard]] QString Extension(const QString &name) {
	const auto slash = std::max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
	const auto base = name.mid(slash + 1);
	const auto dot = base.lastIndexOf('.');
	return (dot < 0) ? QString() : base.mid(dot + 1).trimmed().toLower();
}

[[nodiscard]] bool IsBidiControl(char32_t ch) {
	return (ch >= 0x202A && ch <= 0x202E)
		|| (ch >= 0x2066 && ch <= 0x2069)
		|| ch == 0x200E
		|| ch == 0x200F
		|| ch == 0x061C;
}

[[nodiscard]] bool IsZeroWidth(char32_t ch) {
	return (ch >= 0x200B && ch <= 0x200D) || ch == 0xFEFF || ch == 0x2060;
}

[[nodiscard]] QString MakeControlsVisible(const QString &text) {
	auto result = QString();
	for (const auto ch : text.toUcs4()) {
		if (IsBidiControl(ch) || IsZeroWidth(ch)) {
			result += QStringLiteral("<U+%1>").arg(
				QString::number(uint(ch), 16).toUpper().rightJustified(4, '0'));
		} else {
			const auto c = char32_t(ch);
			result += QString::fromUcs4(&c, 1);
		}
	}
	return result;
}

// --- Links ---

struct Brand {
	const char *name;
	const char *legit; // Space separated registrable domains.
};

[[nodiscard]] const std::vector<Brand> &Brands() {
	static const auto result = std::vector<Brand>{
		{ "telegram", "telegram.org t.me telegram.me telegram.dog "
			"telesco.pe telegra.ph fragment.com" },
		{ "paypal", "paypal.com paypal.me" },
		{ "google", "google.com goo.gl youtube.com gmail.com" },
		{ "gmail", "gmail.com google.com" },
		{ "microsoft", "microsoft.com live.com office.com "
			"microsoftonline.com outlook.com azure.com windows.com" },
		{ "office365", "office.com microsoft.com office365.com" },
		{ "outlook", "outlook.com live.com microsoft.com office.com" },
		{ "apple", "apple.com icloud.com" },
		{ "icloud", "icloud.com apple.com" },
		{ "amazon", "amazon.com aws.amazon.com amazonaws.com" },
		{ "facebook", "facebook.com fb.com fb.me meta.com" },
		{ "instagram", "instagram.com" },
		{ "whatsapp", "whatsapp.com whatsapp.net wa.me" },
		{ "binance", "binance.com" },
		{ "coinbase", "coinbase.com" },
		{ "metamask", "metamask.io" },
		{ "tonkeeper", "tonkeeper.com" },
		{ "trustwallet", "trustwallet.com" },
		{ "steamcommunity", "steamcommunity.com" },
		{ "steampowered", "steampowered.com" },
		{ "discord", "discord.com discord.gg discordapp.com" },
		{ "netflix", "netflix.com" },
		{ "github", "github.com github.io githubusercontent.com" },
		{ "linkedin", "linkedin.com" },
		{ "payme", "payme.uz paycom.uz" },
		{ "uzcard", "uzcard.uz" },
		{ "humocard", "humocard.uz" },
		{ "kapitalbank", "kapitalbank.uz" },
		{ "hamkorbank", "hamkorbank.uz" },
		{ "agrobank", "agrobank.uz" },
		{ "uzum", "uzum.uz uzumbank.uz" },
		{ "gosuslugi", "gosuslugi.ru" },
		{ "sberbank", "sberbank.ru sber.ru" },
		{ "tinkoff", "tinkoff.ru tbank.ru" },
	};
	return result;
}

// Multi-label suffixes that act like TLDs, including free hosting.
[[nodiscard]] const Set &CompoundSuffixes() {
	static const auto result = MakeSet(
		"co.uk org.uk ac.uk gov.uk com.au net.au co.jp com.br com.tr "
		"co.in com.cn com.ua co.za com.uz org.uz net.uz gov.uz edu.uz "
		"co.uz com.kz gov.kz org.kz com.ru msk.ru spb.ru com.tj com.kg "
		"github.io pages.dev workers.dev vercel.app netlify.app "
		"herokuapp.com firebaseapp.com web.app appspot.com glitch.me "
		"repl.co replit.dev ngrok.io ngrok-free.app ngrok.app "
		"trycloudflare.com azurewebsites.net cloudfront.net "
		"blogspot.com wixsite.com weebly.com 000webhostapp.com "
		"duckdns.org ddns.net no-ip.org loca.lt serveo.net "
		"r2.dev onrender.com fly.dev railway.app");
	return result;
}

[[nodiscard]] const Set &FreeHostingSuffixes() {
	static const auto result = MakeSet(
		"github.io pages.dev workers.dev vercel.app netlify.app "
		"herokuapp.com firebaseapp.com web.app appspot.com glitch.me "
		"repl.co replit.dev ngrok.io ngrok-free.app ngrok.app "
		"trycloudflare.com azurewebsites.net blogspot.com wixsite.com "
		"weebly.com 000webhostapp.com duckdns.org ddns.net no-ip.org "
		"loca.lt serveo.net r2.dev onrender.com fly.dev railway.app");
	return result;
}

[[nodiscard]] const Set &Shorteners() {
	static const auto result = MakeSet(
		"bit.ly bitly.com tinyurl.com t.co goo.gl is.gd v.gd cutt.ly "
		"rb.gy ow.ly buff.ly shorturl.at tiny.cc rebrand.ly s.id "
		"clck.ru qps.ru u.to bit.do t.ly tiny.one shorte.st adf.ly "
		"lnkd.in rotf.lol 2u.pw clk.sh ouo.io");
	return result;
}

[[nodiscard]] const Set &SuspiciousTlds() {
	static const auto result = MakeSet(
		"zip mov xyz top tk ml ga cf gq click country work support rest "
		"cam icu buzz lol sbs cfd bond quest monster cyou beauty hair "
		"loan win bid review men date racing download stream gdn kim");
	return result;
}

[[nodiscard]] const Set &TrackingParams() {
	static const auto result = MakeSet(
		"fbclid gclid dclid gbraid wbraid msclkid yclid ysclid igshid igsh "
		"mc_cid mc_eid _hsenc _hsmi mkt_tok ref_src ref_url oly_anon_id "
		"oly_enc_id vero_id rb_clickid __s wickedid twclid ttclid "
		"li_fat_id epik _ga _gl spm scm srsltid");
	return result;
}

[[nodiscard]] const QStringList &PhishingKeywords() {
	static const auto result = QStringList{
		"login", "signin", "sign-in", "verify", "verification", "secure",
		"account", "update", "wallet", "recover", "unlock", "airdrop",
		"claim", "giveaway", "bonus", "premium", "gift", "auth",
		"password", "confirm", "support", "security", "kyc", "suspend",
		"blocked", "reward", "prize", "free",
	};
	return result;
}

[[nodiscard]] int EditDistance(const QString &a, const QString &b) {
	const auto n = a.size();
	const auto m = b.size();
	auto prev = std::vector<int>(m + 1);
	auto curr = std::vector<int>(m + 1);
	for (auto j = 0; j <= m; ++j) {
		prev[j] = j;
	}
	for (auto i = 1; i <= n; ++i) {
		curr[0] = i;
		for (auto j = 1; j <= m; ++j) {
			const auto cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
			curr[j] = std::min({
				prev[j] + 1,
				curr[j - 1] + 1,
				prev[j - 1] + cost });
		}
		std::swap(prev, curr);
	}
	return prev[m];
}

// Undo common visual tricks: digits for letters and letter pairs.
[[nodiscard]] QString NormalizeLookalike(QString label) {
	static const auto cyrillic = QString::fromUtf8("аеорсухіјѕԁһӏвкмнт");
	static const auto latin = QString::fromLatin1("aeopcyxijsdhlbkmht");
	for (auto i = 0; i != cyrillic.size(); ++i) {
		label.replace(cyrillic[i], latin[i]);
	}
	label.replace("rn", "m");
	label.replace("vv", "w");
	label.replace("cl", "d");
	label.replace('0', 'o');
	label.replace('1', 'l');
	label.replace('3', 'e');
	label.replace('4', 'a');
	label.replace('5', 's');
	label.replace('7', 't');
	label.replace('8', 'b');
	label.replace('i', 'l');
	return label;
}

[[nodiscard]] bool IsLatinLookalikeCyrillic(char32_t ch) {
	static const auto list = QString::fromUtf8(
		"аеорсухіјѕԁһӏвкмнтАЕОРСУХІЈЅВКМНТ").toUcs4();
	return list.contains(ch);
}

struct ScriptInfo {
	bool latin = false;
	bool cyrillic = false;
	bool greek = false;
	bool other = false;
	bool onlyLookalikes = true;
};

[[nodiscard]] ScriptInfo Scripts(const QString &label) {
	auto result = ScriptInfo();
	for (const auto ch : label.toUcs4()) {
		if (ch < 0x80) {
			if (QChar::isLetter(ch)) {
				result.latin = true;
			}
			continue;
		}
		switch (QChar::script(ch)) {
		case QChar::Script_Latin: result.latin = true; break;
		case QChar::Script_Cyrillic: result.cyrillic = true; break;
		case QChar::Script_Greek: result.greek = true; break;
		case QChar::Script_Common:
		case QChar::Script_Inherited: break;
		default: result.other = true; break;
		}
		if (!IsLatinLookalikeCyrillic(ch)) {
			result.onlyLookalikes = false;
		}
	}
	return result;
}

[[nodiscard]] std::optional<std::array<int, 4>> ParseIPv4(const QString &host) {
	static const auto re = QRegularExpression(
		"^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
	const auto match = re.match(host);
	if (!match.hasMatch()) {
		return std::nullopt;
	}
	auto result = std::array<int, 4>();
	for (auto i = 0; i != 4; ++i) {
		result[i] = match.captured(i + 1).toInt();
		if (result[i] > 255) {
			return std::nullopt;
		}
	}
	return result;
}

[[nodiscard]] QString PrivateRangeName(const std::array<int, 4> &ip) {
	if (ip[0] == 127) {
		return QStringLiteral("этот компьютер (loopback)");
	} else if (ip[0] == 10
		|| (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31)
		|| (ip[0] == 192 && ip[1] == 168)) {
		return QStringLiteral("адрес локальной сети");
	} else if (ip[0] == 169 && ip[1] == 254) {
		return QStringLiteral("link-local адрес");
	} else if (ip[0] == 0) {
		return QStringLiteral("недопустимый адрес 0.x.x.x");
	}
	return QString();
}

[[nodiscard]] QUrl ParseUserUrl(const QString &url) {
	const auto trimmed = url.trimmed();
	static const auto hasScheme = QRegularExpression(
		"^[a-zA-Z][a-zA-Z0-9+.-]*:");
	return hasScheme.match(trimmed).hasMatch()
		? QUrl(trimmed)
		: QUrl::fromUserInput(trimmed);
}

// QUrl silently normalizes "http://3232235777/" to "192.168.1.1",
// so the obfuscation is looked for in the original text.
[[nodiscard]] QString RawHost(const QString &url) {
	static const auto re = QRegularExpression(
		"^[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^/?#@]*@)?([^/?#:]+)");
	const auto match = re.match(url.trimmed());
	return match.hasMatch() ? match.captured(1).toLower() : QString();
}

void AnalyzeHost(
		UrlReport &result,
		const QUrl &parsed,
		const QString &original) {
	const auto ascii = parsed.host(QUrl::FullyEncoded).toLower();
	auto host = ascii;
	while (host.endsWith('.')) {
		host.chop(1);
	}
	result.asciiHost = host;
	result.host = QUrl::fromAce(
		host.toLatin1(),
		QUrl::IgnoreIDNWhitelist);
	if (host.isEmpty()) {
		return;
	}

	// IP literals and obfuscated numeric hosts.
	static const auto numeric = QRegularExpression(
		"^(0x[0-9a-f]+|\\d+)(\\.(0x[0-9a-f]+|\\d+))*$");
	const auto raw = RawHost(original);
	if (!raw.isEmpty()
		&& raw != host
		&& numeric.match(raw).hasMatch()
		&& !ParseIPv4(raw)) {
		result.add(
			Severity::Critical,
			QStringLiteral("Хост \"%1\" — это замаскированная (десятичная, "
				"восьмеричная или шестнадцатеричная) запись IP-адреса %2.").arg(raw, host));
	}
	if (host.startsWith('[')) {
		result.add(
			Severity::High,
			QStringLiteral("Ссылка использует IPv6-адрес вместо доменного имени."));
		return;
	} else if (const auto ip = ParseIPv4(host)) {
		result.add(
			Severity::High,
			QStringLiteral("Ссылка использует IP-адрес (%1) вместо доменного имени.").arg(host));
		if (const auto range = PrivateRangeName(*ip); !range.isEmpty()) {
			result.add(
				Severity::Warning,
				QStringLiteral("Адрес указывает на %1. Вредоносные ссылки так атакуют "
					"роутер или локальные сервисы.").arg(
					range));
		}
		return;
	}
	if (numeric.match(host).hasMatch()) {
		result.add(
			Severity::Critical,
			QStringLiteral("Хост \"%1\" — это замаскированный (десятичный, "
				"восьмеричный или шестнадцатеричный) IP-адрес.").arg(host));
		return;
	}

	result.registrableDomain = RegistrableDomain(host);
	const auto labels = host.split('.');
	const auto tld = labels.back();
	const auto unicodeLabels = result.host.split('.');

	// IDN and homoglyphs.
	if (host.contains(QStringLiteral("xn--"))) {
		auto mixed = false;
		auto confusable = false;
		for (const auto &label : unicodeLabels) {
			const auto scripts = Scripts(label);
			const auto count = int(scripts.latin)
				+ int(scripts.cyrillic)
				+ int(scripts.greek)
				+ int(scripts.other);
			if (count > 1) {
				mixed = true;
			} else if ((scripts.cyrillic || scripts.greek)
				&& scripts.onlyLookalikes) {
				confusable = true;
			}
		}
		if (mixed) {
			result.add(
				Severity::Critical,
				QStringLiteral("Домен смешивает буквы разных алфавитов (атака "
					"гомоглифами). Настоящий адрес: %1").arg(
					host));
		} else if (confusable) {
			result.add(
				Severity::Critical,
				QStringLiteral("Домен написан нелатинскими буквами, которые выглядят как "
					"латинские. Настоящий адрес: %1").arg(host));
		} else {
			result.add(
				Severity::Notice,
				QStringLiteral("Интернационализированный домен, настоящий адрес: %1").arg(host));
		}
	}

	// Brand impersonation and typosquatting.
	const auto registrable = result.registrableDomain;
	const auto isLegitFor = [&](const Brand &brand) {
		const auto legit = QString::fromLatin1(brand.legit).split(' ');
		return std::any_of(legit.begin(), legit.end(), [&](
				const QString &domain) {
			return host == domain || host.endsWith('.' + domain);
		});
	};
	for (const auto &brand : Brands()) {
		const auto name = QString::fromLatin1(brand.name);
		if (isLegitFor(brand)) {
			continue;
		}
		auto reported = false;
		for (auto i = 0; i != labels.size() - 1; ++i) {
			const auto label = (unicodeLabels.size() == labels.size())
				? unicodeLabels[i].toLower()
				: labels[i];
			if (label.contains(name)) {
				result.add(
					Severity::High,
					QStringLiteral("Адрес упоминает \"%1\", но настоящий сайт — %2, это не "
						"официальный домен %1.").arg(
						name,
						registrable));
				reported = true;
				break;
			}
			const auto normalized = NormalizeLookalike(label);
			const auto limit = (name.size() >= 7) ? 2 : 1;
			const auto pieces = normalized.split('-');
			for (const auto &piece : pieces) {
				if (name.size() < 5 || piece.size() < 4) {
					continue;
				}
				const auto distance = EditDistance(piece, name);
				if (distance <= limit && piece != name) {
					result.add(
						Severity::High,
						QStringLiteral("\"%1\" похоже на искажённое \"%2\" (тайпсквоттинг).").arg(label, name));
					reported = true;
					break;
				} else if (piece == name && label != name) {
					result.add(
						Severity::High,
						QStringLiteral("\"%1\" имитирует \"%2\", заменяя буквы похожими символами.").arg(
							label,
							name));
					reported = true;
					break;
				}
			}
			if (reported) {
				break;
			}
		}
		if (reported) {
			break;
		}
	}

	if (tld == QStringLiteral("onion") || tld == QStringLiteral("i2p")) {
		result.add(
			Severity::Warning,
			QStringLiteral("Адрес сети %1: открывается только через "
				"Tor/I2P, часто ведёт в даркнет. Ваш обычный браузер "
				"может раскрыть IP при попытке открыть.").arg(
				tld == QStringLiteral("onion")
					? QStringLiteral("Tor (.onion)")
					: QStringLiteral("I2P")));
	}
	if (Shorteners().contains(host)) {
		result.add(
			Severity::Warning,
			QStringLiteral("Это сокращатель ссылок: настоящий адрес скрыт до открытия."));
	}
	for (const auto &suffix : FreeHostingSuffixes()) {
		if (host.endsWith('.' + suffix)) {
			result.add(
				Severity::Warning,
				QStringLiteral("Размещено на бесплатном хостинге или туннеле (%1), их "
					"часто используют для фишинга.").arg(suffix));
			break;
		}
	}
	if (SuspiciousTlds().contains(tld)) {
		result.add(
			Severity::Warning,
			QStringLiteral("Доменная зона \".%1\" массово используется для спама и "
				"фишинга.").arg(tld));
	}
	if (labels.size() >= 5) {
		result.add(
			Severity::Notice,
			QStringLiteral("Необычно глубокая цепочка поддоменов (%1 уровней).").arg(labels.size()));
	}
	if (result.host.count('-') >= 3) {
		result.add(
			Severity::Notice,
			QStringLiteral("Много дефисов в имени домена — типично для фишинговых "
				"доменов."));
	}
}

// --- Indicators ---

struct Match {
	IocType type = IocType::Url;
	int from = 0;
	int till = 0;
	QString value;
};

[[nodiscard]] const Set &ProgrammingExtensions() {
	static const auto result = MakeSet(
		"py sh md rs cc so cs pl ps rb ts js h c cpp hpp go kt mm jsx tsx "
		"txt log exe dll bin dat json xml yml yaml ini cfg conf pdf doc "
		"docx xls xlsx png jpg jpeg gif bmp svg zip rar gz tar mp4 mp3 "
		"html htm php css java class jar apk lnk bat ps1 vbs tmp bak sys "
		"iso img msi");
	return result;
}

[[nodiscard]] const Set &GenericTlds() {
	static const auto result = MakeSet(
		"com net org info biz edu gov mil int pro name mobi asia tel "
		"xyz top online site club shop app dev tech store live link "
		"click today news space website cloud email zip mov icu buzz "
		"cam rest work support country lol sbs cfd bond quest cyou "
		"monster ltd group company services finance money bank exchange "
		"capital crypto wallet network systems solutions agency digital "
		"media world global center tools page blog art design studio fun "
		"game games run host onion i2p");
	return result;
}

[[nodiscard]] bool IsLikelyDomain(const QString &domain) {
	const auto labels = domain.split('.');
	if (labels.size() < 2) {
		return false;
	}
	const auto tld = labels.back().toLower();
	if (labels.size() == 2 && ProgrammingExtensions().contains(tld)) {
		return false;
	}
	return (tld.size() == 2) || GenericTlds().contains(tld);
}

[[nodiscard]] QString TrimUrlTail(QString url) {
	static const auto trailing = QString::fromLatin1(".,;:!?'\"]>}*");
	while (!url.isEmpty()) {
		const auto last = url.back();
		if (trailing.contains(last)) {
			url.chop(1);
		} else if (last == ')' && url.count('(') < url.count(')')) {
			url.chop(1);
		} else {
			break;
		}
	}
	return url;
}

[[nodiscard]] bool ValidIPv6(const QString &value) {
	if (value.count(QStringLiteral("::")) > 1) {
		return false;
	}
	const auto compressed = value.contains(QStringLiteral("::"));
	const auto groups = value.split(':');
	auto nonEmpty = 0;
	auto allTwo = true;
	for (const auto &group : groups) {
		if (group.size() > 4) {
			return false;
		} else if (!group.isEmpty()) {
			++nonEmpty;
		}
		if (group.size() != 2) {
			allTwo = false;
		}
	}
	if (allTwo && groups.size() == 6) {
		return false; // MAC address.
	} else if (!compressed && groups.size() != 8) {
		return false;
	} else if (compressed && (groups.size() > 9 || nonEmpty == 0)) {
		return false;
	}
	return compressed ? (nonEmpty >= 1) : true;
}

[[nodiscard]] std::vector<Match> FindMatches(const QString &text) {
	using Option = QRegularExpression::PatternOption;
	struct Rule {
		IocType type;
		QRegularExpression re;
	};
	static const auto rules = std::vector<Rule>{
		{ IocType::Url, QRegularExpression(
			"\\b(?:https?|ftp|sftp|wss?|tonsite)://[^\\s<>\"'`]+",
			Option::CaseInsensitiveOption) },
		{ IocType::Email, QRegularExpression(
			"(?<![\\w.+-])[\\w.+-]{1,64}@"
			"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,24}\\b",
			Option::CaseInsensitiveOption) },
		{ IocType::RegistryKey, QRegularExpression(
			"\\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\\\[^\\s\"'<>]+") },
		{ IocType::WindowsPath, QRegularExpression(
			"(?:\\b[A-Za-z]:|%[A-Za-z_]+%)\\\\"
			"(?:[^\\\\/:*?\"<>|\\s]+\\\\)*[^\\\\/:*?\"<>|\\s]*") },
		{ IocType::CVE, QRegularExpression(
			"\\bCVE-\\d{4}-\\d{4,7}\\b",
			Option::CaseInsensitiveOption) },
		{ IocType::MitreAttack, QRegularExpression(
			"\\b(?:T[1-9]\\d{3}(?:\\.\\d{3})?|TA00\\d\\d)\\b") },
		{ IocType::SHA512, QRegularExpression(
			"(?<![0-9a-fA-Fx])[0-9a-fA-F]{128}(?![0-9a-fA-F])") },
		{ IocType::SHA256, QRegularExpression(
			"(?<![0-9a-fA-Fx])[0-9a-fA-F]{64}(?![0-9a-fA-F])") },
		{ IocType::Ethereum, QRegularExpression(
			"\\b0x[0-9a-fA-F]{40}(?![0-9a-fA-F])") },
		{ IocType::SHA1, QRegularExpression(
			"(?<![0-9a-fA-Fx])[0-9a-fA-F]{40}(?![0-9a-fA-F])") },
		{ IocType::MD5, QRegularExpression(
			"(?<![0-9a-fA-Fx])[0-9a-fA-F]{32}(?![0-9a-fA-F])") },
		{ IocType::Ton, QRegularExpression(
			"(?<![\\w-])(?:EQ|UQ|kQ|0Q)[A-Za-z0-9_-]{46}(?![\\w-])") },
		{ IocType::Bitcoin, QRegularExpression(
			"(?<![\\w])(?:bc1[ac-hj-np-z02-9]{11,71}"
			"|[13][a-km-zA-HJ-NP-Z1-9]{25,34})(?![\\w])") },
		{ IocType::IPv4, QRegularExpression(
			"(?<![\\d.])(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}"
			"(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?!\\.?\\d)") },
		{ IocType::IPv6, QRegularExpression(
			"(?<![\\w:.])(?:[0-9a-fA-F]{0,4}:){2,8}[0-9a-fA-F]{0,4}"
			"(?![\\w:])") },
		{ IocType::TelegramUsername, QRegularExpression(
			"(?<![\\w@./])@[A-Za-z][A-Za-z0-9_]{3,31}(?![\\w@])") },
		{ IocType::Domain, QRegularExpression(
			"(?<![\\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+"
			"[a-z]{2,24}(?![\\w-]|\\.\\w)",
			Option::CaseInsensitiveOption) },
	};

	auto result = std::vector<Match>();
	const auto overlaps = [&](int from, int till) {
		return std::any_of(result.begin(), result.end(), [&](
				const Match &m) {
			return (from < m.till) && (m.from < till);
		});
	};
	for (const auto &rule : rules) {
		auto i = rule.re.globalMatch(text);
		while (i.hasNext()) {
			const auto match = i.next();
			auto value = match.captured(0);
			const auto from = int(match.capturedStart(0));
			if (rule.type == IocType::Url) {
				value = TrimUrlTail(value);
			} else if (rule.type == IocType::WindowsPath
				|| rule.type == IocType::RegistryKey) {
				value = TrimUrlTail(value);
			}
			const auto till = from + int(value.size());
			if (value.isEmpty() || overlaps(from, till)) {
				continue;
			} else if (rule.type == IocType::Domain
				&& !IsLikelyDomain(value)) {
				continue;
			} else if (rule.type == IocType::IPv6 && !ValidIPv6(value)) {
				continue;
			}
			switch (rule.type) {
			case IocType::CVE: value = value.toUpper(); break;
			case IocType::Domain: value = value.toLower(); break;
			case IocType::MD5:
			case IocType::SHA1:
			case IocType::SHA256:
			case IocType::SHA512: value = value.toLower(); break;
			default: break;
			}
			result.push_back({ rule.type, from, till, value });
		}
	}
	std::sort(result.begin(), result.end(), [](
			const Match &a,
			const Match &b) {
		return a.from < b.from;
	});
	return result;
}

[[nodiscard]] QString CsvEscape(const QString &value) {
	if (value.contains(',') || value.contains('"') || value.contains('\n')) {
		return '"' + QString(value).replace("\"", "\"\"") + '"';
	}
	return value;
}

} // namespace

QString SeverityName(Severity severity) {
	switch (severity) {
	case Severity::Info: return QStringLiteral("Инфо");
	case Severity::Notice: return QStringLiteral("Низкий");
	case Severity::Warning: return QStringLiteral("Средний");
	case Severity::High: return QStringLiteral("Высокий");
	case Severity::Critical: return QStringLiteral("Критический");
	}
	return QString();
}

Severity Report::maxSeverity() const {
	auto result = Severity::Info;
	for (const auto &finding : findings) {
		result = std::max(result, finding.severity);
	}
	return result;
}

bool Report::atLeast(Severity severity) const {
	return !findings.empty() && (maxSeverity() >= severity);
}

void Report::add(Severity severity, QString text) {
	findings.push_back({ severity, std::move(text) });
}

QString RegistrableDomain(const QString &host) {
	const auto labels = host.toLower().split('.', Qt::SkipEmptyParts);
	if (labels.size() <= 2) {
		return labels.join('.');
	}
	const auto lastTwo = labels.mid(labels.size() - 2).join('.');
	const auto take = CompoundSuffixes().contains(lastTwo) ? 3 : 2;
	return labels.mid(labels.size() - take).join('.');
}

QString StripTracking(const QString &url, QStringList *removed) {
	auto parsed = QUrl(url);
	if (!parsed.isValid() || !parsed.hasQuery()) {
		return url;
	}
	const auto host = parsed.host().toLower();
	const auto shareSi = host.endsWith(QStringLiteral("youtube.com"))
		|| host == QStringLiteral("youtu.be")
		|| host.endsWith(QStringLiteral("spotify.com"));
	auto query = QUrlQuery(parsed);
	auto kept = QList<QPair<QString, QString>>();
	auto changed = false;
	for (const auto &[key, value] : query.queryItems(QUrl::FullyEncoded)) {
		const auto lower = key.toLower();
		const auto tracking = lower.startsWith(QStringLiteral("utm_"))
			|| TrackingParams().contains(lower)
			|| (shareSi && lower == QStringLiteral("si"))
			|| (shareSi && lower == QStringLiteral("feature")
				&& value == QStringLiteral("share"));
		if (tracking) {
			changed = true;
			if (removed) {
				removed->push_back(key);
			}
		} else {
			kept.push_back({ key, value });
		}
	}
	if (!changed) {
		return url;
	}
	auto rebuilt = QUrlQuery();
	rebuilt.setQueryItems(kept);
	parsed.setQuery(
		rebuilt.isEmpty()
			? QString()
			: rebuilt.query(QUrl::FullyEncoded),
		QUrl::StrictMode);
	if (kept.isEmpty()) {
		parsed.setQuery(QString());
	}
	return QString::fromUtf8(parsed.toEncoded());
}

UrlReport AnalyzeUrl(const QString &url) {
	auto result = UrlReport();
	const auto parsed = ParseUserUrl(url);
	result.scheme = parsed.scheme().toLower();
	result.cleanUrl = StripTracking(
		QString::fromUtf8(parsed.toEncoded()),
		&result.trackingParams);

	if (!parsed.isValid()) {
		result.add(
			Severity::Warning,
			QStringLiteral("Ссылка повреждена или некорректна."));
		return result;
	}

	const auto &scheme = result.scheme;
	if (scheme == QStringLiteral("javascript")
		|| scheme == QStringLiteral("vbscript")
		|| scheme == QStringLiteral("data")) {
		result.add(
			Severity::Critical,
			QStringLiteral("Ссылки \"%1:\" выполняют код или встраивают содержимое — "
				"никогда их не открывайте.").arg(scheme));
		return result;
	} else if (scheme == QStringLiteral("file")
		|| scheme == QStringLiteral("smb")
		|| scheme == QStringLiteral("ms-msdt")
		|| scheme == QStringLiteral("search-ms")
		|| scheme == QStringLiteral("ms-officecmd")) {
		result.add(
			Severity::Critical,
			QStringLiteral("Ссылки \"%1:\" могут открыть локальные файлы или слить "
				"ваши учётные данные Windows (NTLM-хеш).").arg(scheme));
		return result;
	} else if (scheme == QStringLiteral("http")) {
		result.add(
			Severity::Notice,
			QStringLiteral("Соединение не зашифровано (http)."));
	} else if (scheme == QStringLiteral("ftp")) {
		result.add(
			Severity::Notice,
			QStringLiteral("Незашифрованная FTP-ссылка."));
	}

	if (!parsed.userInfo().isEmpty()) {
		result.add(
			Severity::Critical,
			QStringLiteral("Всё до \"@\" (\"%1\") браузер игнорирует. Настоящий сайт — "
				"%2.").arg(
				parsed.userInfo(),
				parsed.host()));
	}

	AnalyzeHost(result, parsed, url);

	const auto port = parsed.port();
	if (port > 0 && port != 80 && port != 443) {
		result.add(
			Severity::Warning,
			QStringLiteral("Нестандартный порт %1.").arg(port));
	}

	const auto path = parsed.path();
	const auto fileName = path.mid(path.lastIndexOf('/') + 1);
	if (!fileName.isEmpty() && fileName.contains('.')) {
		const auto file = AnalyzeFileName(
			QUrl::fromPercentEncoding(fileName.toUtf8()));
		if (file.executable) {
			result.add(
				Severity::High,
				QStringLiteral("Ссылка напрямую скачивает исполняемый файл (.%1).").arg(file.realExtension));
		} else if (file.atLeast(Severity::Warning)) {
			result.add(
				Severity::Warning,
				QStringLiteral("Ссылка скачивает опасный тип файла (.%1).").arg(file.realExtension));
		}
	}

	// Open redirects: a full address hidden in a parameter.
	const auto query = QUrlQuery(parsed);
	for (const auto &[key, value] : query.queryItems(QUrl::FullyDecoded)) {
		auto decoded = value;
		for (auto i = 0; i != 3 && decoded.contains('%'); ++i) {
			decoded = QUrl::fromPercentEncoding(decoded.toUtf8());
		}
		if (decoded.startsWith(QStringLiteral("http://"), Qt::CaseInsensitive)
			|| decoded.startsWith(
				QStringLiteral("https://"),
				Qt::CaseInsensitive)
			|| decoded.startsWith(QStringLiteral("//"))) {
			const auto target = ParseUserUrl(decoded.startsWith("//")
				? (QStringLiteral("https:") + decoded)
				: decoded);
			const auto targetHost = target.host().toLower();
			if (!targetHost.isEmpty()
				&& RegistrableDomain(targetHost)
					!= result.registrableDomain) {
				result.redirectTarget = decoded;
				result.add(
					Severity::Warning,
					QStringLiteral("Параметр \"%1\" перенаправляет на другой сайт: %2").arg(key, targetHost));
				const auto inner = AnalyzeUrl(decoded);
				for (const auto &finding : inner.findings) {
					if (finding.severity >= Severity::Warning) {
						result.add(
							finding.severity,
							QStringLiteral("Цель перенаправления: ")
								+ finding.text);
					}
				}
				break;
			}
		}
	}

	auto keywords = QStringList();
	const auto lowered = (result.asciiHost + path).toLower();
	for (const auto &keyword : PhishingKeywords()) {
		if (lowered.contains(keyword)) {
			keywords.push_back(keyword);
		}
	}
	if (!keywords.isEmpty()) {
		result.add(
			(keywords.size() >= 2) ? Severity::Warning : Severity::Notice,
			QStringLiteral("Фишинговые слова в адресе: %1").arg(keywords.join(QStringLiteral(", "))));
	}

	const auto encoded = QString::fromUtf8(parsed.toEncoded());
	if (encoded.contains(QStringLiteral("%25"))) {
		result.add(
			Severity::Notice,
			QStringLiteral("Адрес закодирован дважды — это может скрывать его "
				"настоящее содержимое."));
	}
	if (encoded.size() > 300) {
		result.add(
			Severity::Info,
			QStringLiteral("Очень длинный адрес (%1 символов).").arg(
				encoded.size()));
	}
	if (!result.trackingParams.isEmpty()) {
		result.add(
			Severity::Info,
			QStringLiteral("Параметры слежки: %1").arg(
				result.trackingParams.join(QStringLiteral(", "))));
	}
	return result;
}

QString IocTypeName(IocType type) {
	switch (type) {
	case IocType::Url: return QStringLiteral("url");
	case IocType::Domain: return QStringLiteral("domain");
	case IocType::IPv4: return QStringLiteral("ipv4");
	case IocType::IPv6: return QStringLiteral("ipv6");
	case IocType::Email: return QStringLiteral("email");
	case IocType::MD5: return QStringLiteral("md5");
	case IocType::SHA1: return QStringLiteral("sha1");
	case IocType::SHA256: return QStringLiteral("sha256");
	case IocType::SHA512: return QStringLiteral("sha512");
	case IocType::CVE: return QStringLiteral("cve");
	case IocType::MitreAttack: return QStringLiteral("mitre-attack");
	case IocType::Bitcoin: return QStringLiteral("btc");
	case IocType::Ethereum: return QStringLiteral("eth");
	case IocType::Ton: return QStringLiteral("ton");
	case IocType::TelegramUsername: return QStringLiteral("telegram");
	case IocType::RegistryKey: return QStringLiteral("registry");
	case IocType::WindowsPath: return QStringLiteral("filepath");
	}
	return QString();
}

QString Refang(const QString &text) {
	using Option = QRegularExpression::PatternOption;
	static const auto rules = std::vector<std::pair<QRegularExpression, QString>>{
		{ QRegularExpression(
			"\\bh(?:xx|\\*\\*|XX)p(s?)",
			Option::CaseInsensitiveOption), QStringLiteral("http\\1") },
		{ QRegularExpression(
			"\\bfxp\\b",
			Option::CaseInsensitiveOption), QStringLiteral("ftp") },
		{ QRegularExpression("\\[://\\]"), QStringLiteral("://") },
		{ QRegularExpression("\\[:\\]//"), QStringLiteral("://") },
		{ QRegularExpression("\\[:\\]"), QStringLiteral(":") },
		{ QRegularExpression("\\[/\\]"), QStringLiteral("/") },
		{ QRegularExpression(
			"\\s?[\\[\\(\\{](?:\\.|dot)[\\]\\)\\}]\\s?",
			Option::CaseInsensitiveOption), QStringLiteral(".") },
		{ QRegularExpression("\\\\\\."), QStringLiteral(".") },
		{ QRegularExpression(
			"\\s?[\\[\\(\\{](?:@|at)[\\]\\)\\}]\\s?",
			Option::CaseInsensitiveOption), QStringLiteral("@") },
	};
	auto result = text;
	for (const auto &[re, replacement] : rules) {
		result.replace(re, replacement);
	}
	return result;
}

QString Defang(const QString &indicator) {
	auto result = indicator;
	const auto schemeEnd = result.indexOf(QStringLiteral("://"));
	if (schemeEnd > 0) {
		auto scheme = result.left(schemeEnd);
		if (scheme.compare(QStringLiteral("http"), Qt::CaseInsensitive) == 0) {
			scheme = QStringLiteral("hxxp");
		} else if (scheme.compare(
				QStringLiteral("https"),
				Qt::CaseInsensitive) == 0) {
			scheme = QStringLiteral("hxxps");
		} else if (scheme.compare(
				QStringLiteral("ftp"),
				Qt::CaseInsensitive) == 0) {
			scheme = QStringLiteral("fxp");
		}
		const auto hostStart = schemeEnd + 3;
		auto hostEnd = result.indexOf('/', hostStart);
		if (hostEnd < 0) {
			hostEnd = result.size();
		}
		auto host = result.mid(hostStart, hostEnd - hostStart);
		host.replace('.', QStringLiteral("[.]"));
		host.replace('@', QStringLiteral("[@]"));
		return scheme + QStringLiteral("[://]") + host + result.mid(hostEnd);
	}
	result.replace('.', QStringLiteral("[.]"));
	result.replace('@', QStringLiteral("[@]"));
	if (result.contains(':') && !result.contains('[')) {
		result.replace(':', QStringLiteral("[:]")); // IPv6
	}
	return result;
}

QString DefangText(const QString &text) {
	const auto refanged = Refang(text);
	const auto matches = FindMatches(refanged);
	auto result = QString();
	auto from = 0;
	for (const auto &match : matches) {
		const auto defangable = match.type == IocType::Url
			|| match.type == IocType::Domain
			|| match.type == IocType::IPv4
			|| match.type == IocType::IPv6
			|| match.type == IocType::Email;
		if (!defangable) {
			continue;
		}
		result += refanged.mid(from, match.from - from);
		result += Defang(refanged.mid(match.from, match.till - match.from));
		from = match.till;
	}
	result += refanged.mid(from);
	return result;
}

std::vector<Ioc> ExtractIocs(const QString &text) {
	const auto matches = FindMatches(Refang(text));
	auto result = std::vector<Ioc>();
	const auto push = [&](IocType type, const QString &value) {
		const auto ioc = Ioc{ type, value };
		if (std::find(result.begin(), result.end(), ioc) == result.end()) {
			result.push_back(ioc);
		}
	};
	for (const auto &match : matches) {
		push(match.type, match.value);
		if (match.type == IocType::Url) {
			const auto host = QUrl(match.value).host().toLower();
			if (ParseIPv4(host)) {
				push(IocType::IPv4, host);
			} else if (!host.isEmpty() && host.contains('.')) {
				push(IocType::Domain, host);
			}
		} else if (match.type == IocType::Email) {
			push(
				IocType::Domain,
				match.value.mid(match.value.indexOf('@') + 1).toLower());
		}
	}
	std::stable_sort(result.begin(), result.end(), [](
			const Ioc &a,
			const Ioc &b) {
		return int(a.type) < int(b.type);
	});
	return result;
}

QString FormatIocs(
		const std::vector<Ioc> &iocs,
		IocFormat format,
		bool defanged) {
	const auto value = [&](const Ioc &ioc) {
		const auto defangable = ioc.type == IocType::Url
			|| ioc.type == IocType::Domain
			|| ioc.type == IocType::IPv4
			|| ioc.type == IocType::IPv6
			|| ioc.type == IocType::Email;
		return (defanged && defangable) ? Defang(ioc.value) : ioc.value;
	};
	switch (format) {
	case IocFormat::Text: {
		auto result = QString();
		auto last = std::optional<IocType>();
		for (const auto &ioc : iocs) {
			if (last != ioc.type) {
				if (last) {
					result += '\n';
				}
				result += QStringLiteral("# %1\n").arg(IocTypeName(ioc.type));
				last = ioc.type;
			}
			result += value(ioc) + '\n';
		}
		return result;
	}
	case IocFormat::Csv: {
		auto result = QStringLiteral("type,value\n");
		for (const auto &ioc : iocs) {
			result += IocTypeName(ioc.type) + ',' + CsvEscape(value(ioc)) + '\n';
		}
		return result;
	}
	case IocFormat::Stix: {
		const auto now = QDateTime::currentDateTimeUtc().toString(
			QStringLiteral("yyyy-MM-ddTHH:mm:ss.zzzZ"));
		const auto escape = [](QString value) {
			return value.replace('\\', QStringLiteral("\\\\"))
				.replace('\'', QStringLiteral("\\'"));
		};
		const auto uuid = [] {
			return QUuid::createUuid().toString(QUuid::WithoutBraces);
		};
		auto objects = QJsonArray();
		for (const auto &ioc : iocs) {
			auto pattern = QString();
			const auto v = escape(ioc.value);
			switch (ioc.type) {
			case IocType::Url: pattern = "[url:value = '" + v + "']"; break;
			case IocType::Domain:
				pattern = "[domain-name:value = '" + v + "']";
				break;
			case IocType::IPv4:
				pattern = "[ipv4-addr:value = '" + v + "']";
				break;
			case IocType::IPv6:
				pattern = "[ipv6-addr:value = '" + v + "']";
				break;
			case IocType::Email:
				pattern = "[email-addr:value = '" + v + "']";
				break;
			case IocType::MD5:
				pattern = "[file:hashes.MD5 = '" + v + "']";
				break;
			case IocType::SHA1:
				pattern = "[file:hashes.'SHA-1' = '" + v + "']";
				break;
			case IocType::SHA256:
				pattern = "[file:hashes.'SHA-256' = '" + v + "']";
				break;
			case IocType::SHA512:
				pattern = "[file:hashes.'SHA-512' = '" + v + "']";
				break;
			case IocType::CVE:
				objects.push_back(QJsonObject{
					{ "type", "vulnerability" },
					{ "spec_version", "2.1" },
					{ "id", "vulnerability--" + uuid() },
					{ "created", now },
					{ "modified", now },
					{ "name", ioc.value },
					{ "external_references", QJsonArray{ QJsonObject{
						{ "source_name", "cve" },
						{ "external_id", ioc.value },
					} } },
				});
				continue;
			default: continue;
			}
			objects.push_back(QJsonObject{
				{ "type", "indicator" },
				{ "spec_version", "2.1" },
				{ "id", "indicator--" + uuid() },
				{ "created", now },
				{ "modified", now },
				{ "valid_from", now },
				{ "name", IocTypeName(ioc.type) + ": " + ioc.value },
				{ "pattern", pattern },
				{ "pattern_type", "stix" },
				{ "indicator_types", QJsonArray{ "malicious-activity" } },
			});
		}
		const auto bundle = QJsonObject{
			{ "type", "bundle" },
			{ "id", "bundle--" + uuid() },
			{ "objects", objects },
		};
		return QString::fromUtf8(
			QJsonDocument(bundle).toJson(QJsonDocument::Indented));
	}
	case IocFormat::Misp: {
		auto attributes = QJsonArray();
		for (const auto &ioc : iocs) {
			auto type = QString();
			auto category = QStringLiteral("Network activity");
			switch (ioc.type) {
			case IocType::Url: type = "url"; break;
			case IocType::Domain: type = "domain"; break;
			case IocType::IPv4:
			case IocType::IPv6: type = "ip-dst"; break;
			case IocType::Email: type = "email-src"; break;
			case IocType::MD5: type = "md5"; category = "Payload delivery"; break;
			case IocType::SHA1: type = "sha1"; category = "Payload delivery"; break;
			case IocType::SHA256:
				type = "sha256";
				category = "Payload delivery";
				break;
			case IocType::SHA512:
				type = "sha512";
				category = "Payload delivery";
				break;
			case IocType::CVE:
				type = "vulnerability";
				category = "External analysis";
				break;
			case IocType::Bitcoin:
				type = "btc";
				category = "Financial fraud";
				break;
			case IocType::RegistryKey:
				type = "regkey";
				category = "Persistence mechanism";
				break;
			case IocType::WindowsPath:
				type = "filename";
				category = "Artifacts dropped";
				break;
			default:
				type = "text";
				category = "Other";
				break;
			}
			attributes.push_back(QJsonObject{
				{ "type", type },
				{ "category", category },
				{ "value", ioc.value },
				{ "to_ids", type != "text" },
			});
		}
		const auto event = QJsonObject{ { "Event", QJsonObject{
			{ "info", "SecGram export" },
			{ "date", QDate::currentDate().toString(Qt::ISODate) },
			{ "threat_level_id", "2" },
			{ "analysis", "0" },
			{ "distribution", "0" },
			{ "Attribute", attributes },
		} } };
		return QString::fromUtf8(
			QJsonDocument(event).toJson(QJsonDocument::Indented));
	}
	case IocFormat::TheHive: {
		auto observables = QJsonArray();
		for (const auto &ioc : iocs) {
			auto type = QStringLiteral("other");
			switch (ioc.type) {
			case IocType::Url: type = "url"; break;
			case IocType::Domain: type = "domain"; break;
			case IocType::IPv4:
			case IocType::IPv6: type = "ip"; break;
			case IocType::Email: type = "mail"; break;
			case IocType::MD5:
			case IocType::SHA1:
			case IocType::SHA256:
			case IocType::SHA512: type = "hash"; break;
			case IocType::RegistryKey: type = "registry"; break;
			case IocType::WindowsPath: type = "filename"; break;
			default: break;
			}
			observables.push_back(QJsonObject{
				{ "dataType", type },
				{ "data", ioc.value },
				{ "ioc", type != "other" },
				{ "tags", QJsonArray{ "secgram", IocTypeName(ioc.type) } },
			});
		}
		const auto alert = QJsonObject{
			{ "type", "external" },
			{ "source", "SecGram" },
			{ "sourceRef", QUuid::createUuid().toString(QUuid::WithoutBraces) },
			{ "title", QStringLiteral("SecGram: %1 индикаторов").arg(
				iocs.size()) },
			{ "description", "Индикаторы, извлечённые из Telegram." },
			{ "severity", 2 },
			{ "tlp", 2 },
			{ "observables", observables },
		};
		return QString::fromUtf8(
			QJsonDocument(alert).toJson(QJsonDocument::Indented));
	}
	case IocFormat::Json: {
		auto array = QJsonArray();
		for (const auto &ioc : iocs) {
			array.push_back(QJsonObject{
				{ QStringLiteral("type"), IocTypeName(ioc.type) },
				{ QStringLiteral("value"), value(ioc) },
			});
		}
		return QString::fromUtf8(
			QJsonDocument(array).toJson(QJsonDocument::Indented));
	}
	}
	return QString();
}

FileReport AnalyzeFileName(const QString &name, const QString &mime) {
	auto result = FileReport();
	result.displayName = MakeControlsVisible(name);

	auto clean = QString();
	auto bidi = false;
	auto zeroWidth = false;
	for (const auto ch : name.toUcs4()) {
		if (IsBidiControl(ch)) {
			bidi = true;
		} else if (IsZeroWidth(ch)) {
			zeroWidth = true;
		} else {
			const auto c = char32_t(ch);
			clean += QString::fromUcs4(&c, 1);
		}
	}
	const auto extension = Extension(clean);
	result.realExtension = extension;
	if (bidi) {
		result.add(
			Severity::Critical,
			QStringLiteral("Имя содержит символы смены направления текста (RTLO), "
				"маскирующие настоящее расширение. Настоящее расширение — "
				"\".%1\".").arg(extension));
	}
	if (zeroWidth) {
		result.add(
			Severity::Warning,
			QStringLiteral("Имя содержит невидимые символы нулевой ширины."));
	}

	const auto executable = ExecutableExtensions().contains(extension);
	result.executable = executable;
	if (executable) {
		result.add(
			Severity::High,
			QStringLiteral("\".%1\" — исполняемый файл или скрипт. Он может получить "
				"полный контроль над компьютером или телефоном.").arg(extension));
	} else if (MacroExtensions().contains(extension)) {
		result.add(
			Severity::High,
			QStringLiteral("\".%1\" — документ Office с макросами. Никогда не "
				"включайте макросы в файлах из чатов.").arg(extension));
	} else if (ContainerExtensions().contains(extension)) {
		result.add(
			Severity::Warning,
			QStringLiteral("Образы дисков \".%1\" используют, чтобы обойти "
				"предупреждения Windows (Mark of the Web).").arg(
				extension));
	} else if (ActiveDocumentExtensions().contains(extension)) {
		result.add(
			Severity::Warning,
			QStringLiteral("Файлы \".%1\" могут выполнять скрипты, их используют для "
				"фишинга и HTML smuggling.").arg(extension));
	} else if (LegacyOfficeExtensions().contains(extension)) {
		result.add(
			Severity::Notice,
			QStringLiteral("Старый формат Office, может содержать макросы или "
				"эксплойты. Открывайте только в защищённом режиме."));
	} else if (ArchiveExtensions().contains(extension)) {
		result.add(
			Severity::Notice,
			QStringLiteral("Архив: проверьте содержимое перед распаковкой. Архивы с "
				"паролем обходят антивирус."));
	}

	// Double extensions: "invoice.pdf.exe".
	const auto parts = clean.split('.');
	if (parts.size() >= 3) {
		const auto inner = parts[parts.size() - 2].trimmed().toLower();
		if (LureExtensions().contains(inner)
			&& (executable || MacroExtensions().contains(extension))) {
			result.add(
				Severity::Critical,
				QStringLiteral("Двойное расширение \".%1.%2\": файл притворяется .%1, но "
					"на самом деле это .%2.").arg(
					inner,
					extension));
		}
	}
	static const auto padding = QRegularExpression(
		"(\\s{4,}|_{6,}|\\.{3,}\\s*)\\.?[A-Za-z0-9]{1,8}$");
	if (padding.match(clean).hasMatch() && !extension.isEmpty()) {
		result.add(
			Severity::Critical,
			QStringLiteral("Длинный отступ перед расширением скрывает \".%1\".").arg(extension));
	}

	const auto lowerMime = mime.toLower();
	static const auto executableMimes = MakeSet(
		"application/x-msdownload application/x-dosexec "
		"application/x-msdos-program application/x-executable "
		"application/vnd.android.package-archive application/x-sh "
		"application/java-archive application/x-ms-installer "
		"application/x-msi application/x-elf application/x-mach-binary "
		"application/hta");
	if (!lowerMime.isEmpty()
		&& executableMimes.contains(lowerMime)
		&& !executable) {
		result.add(
			Severity::Critical,
			QStringLiteral("Отправитель указал тип %1 (исполняемый), а имя "
				"заканчивается на \".%2\".").arg(lowerMime, extension));
		result.executable = true;
	}
	return result;
}

QString DetectMagicType(const QByteArray &head, bool *executable) {
	const auto starts = [&](const char *magic, int length, int offset = 0) {
		return head.size() >= offset + length
			&& std::memcmp(head.constData() + offset, magic, length) == 0;
	};
	const auto set = [&](bool value) {
		if (executable) {
			*executable = value;
		}
	};
	set(false);
	if (starts("MZ", 2)) {
		set(true);
		return QStringLiteral("исполняемый файл Windows (PE)");
	} else if (starts("\x7F" "ELF", 4)) {
		set(true);
		return QStringLiteral("исполняемый файл Linux (ELF)");
	} else if (starts("\xFE\xED\xFA\xCE", 4)
		|| starts("\xFE\xED\xFA\xCF", 4)
		|| starts("\xCE\xFA\xED\xFE", 4)
		|| starts("\xCF\xFA\xED\xFE", 4)) {
		set(true);
		return QStringLiteral("исполняемый файл macOS (Mach-O)");
	} else if (starts("\xCA\xFE\xBA\xBE", 4)) {
		set(true);
		return QStringLiteral("Java class или универсальный бинарник macOS");
	} else if (starts("dex\n", 4)) {
		set(true);
		return QStringLiteral("байткод Android DEX");
	} else if (starts("#!", 2)) {
		set(true);
		return QStringLiteral("скрипт с интерпретатором (#!)");
	} else if (starts("\x4C\x00\x00\x00\x01\x14\x02\x00", 8)) {
		set(true);
		return QStringLiteral("ярлык Windows (LNK)");
	} else if (starts("PK\x03\x04", 4)) {
		if (head.contains("AndroidManifest.xml") || head.contains("classes.dex")) {
			set(true);
			return QStringLiteral("приложение Android (APK)");
		} else if (head.contains("vbaProject.bin")) {
			set(true);
			return QStringLiteral("документ Office с макросами VBA");
		} else if (head.contains("META-INF/MANIFEST.MF")) {
			set(true);
			return QStringLiteral("Java-архив (JAR)");
		} else if (head.contains("word/")) {
			return QStringLiteral("документ Word (OOXML)");
		} else if (head.contains("xl/")) {
			return QStringLiteral("книга Excel (OOXML)");
		} else if (head.contains("ppt/")) {
			return QStringLiteral("презентация PowerPoint (OOXML)");
		}
		return QStringLiteral("ZIP-архив");
	} else if (starts("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8)) {
		if (head.contains("_VBA_PROJECT") || head.contains("V\0B\0A")) {
			set(true);
			return QStringLiteral("старый файл Office с макросами VBA");
		}
		return QStringLiteral("составной OLE-файл (старый Office / MSI)");
	} else if (starts("Rar!\x1A\x07", 6)) {
		return QStringLiteral("RAR-архив");
	} else if (starts("7z\xBC\xAF\x27\x1C", 6)) {
		return QStringLiteral("7-Zip-архив");
	} else if (starts("\x1F\x8B", 2)) {
		return QStringLiteral("GZip-архив");
	} else if (starts("%PDF", 4)) {
		if (head.contains("/JavaScript") || head.contains("/JS")) {
			return QStringLiteral("PDF со встроенным JavaScript");
		} else if (head.contains("/Launch") || head.contains("/EmbeddedFile")) {
			return QStringLiteral("PDF с действием запуска / вложенным файлом");
		}
		return QStringLiteral("PDF-документ");
	} else if (starts("{\\rtf", 5)) {
		return QStringLiteral("RTF-документ");
	} else if (starts("\x89PNG", 4)) {
		return QStringLiteral("изображение PNG");
	} else if (starts("\xFF\xD8\xFF", 3)) {
		return QStringLiteral("изображение JPEG");
	} else if (starts("GIF8", 4)) {
		return QStringLiteral("изображение GIF");
	} else if (starts("RIFF", 4) && starts("WEBP", 4, 8)) {
		return QStringLiteral("изображение WebP");
	} else if (starts("ftyp", 4, 4)) {
		return QStringLiteral("видео MP4 / QuickTime");
	} else if (starts("OggS", 4)) {
		return QStringLiteral("медиа Ogg");
	} else if (starts("ID3", 3)) {
		return QStringLiteral("аудио MP3");
	} else if (head.size() > 0x8005 && starts("CD001", 5, 0x8001)) {
		return QStringLiteral("образ диска ISO");
	}
	const auto lower = head.left(1024).toLower();
	if (lower.contains("<svg")) {
		return lower.contains("<script")
			? QStringLiteral("SVG со встроенным скриптом")
			: QStringLiteral("изображение SVG");
	} else if (lower.contains("<html") || lower.contains("<!doctype html")) {
		return lower.contains("<script")
			? QStringLiteral("HTML-страница со скриптами")
			: QStringLiteral("HTML-страница");
	}
	return QString();
}

namespace {

template <typename Feed>
FileHashes ComputeHashesWith(Feed &&feed) {
	auto result = FileHashes();
	auto md5 = QCryptographicHash(QCryptographicHash::Md5);
	auto sha1 = QCryptographicHash(QCryptographicHash::Sha1);
	auto sha256 = QCryptographicHash(QCryptographicHash::Sha256);
	auto head = QByteArray();
	constexpr auto kHeadSize = 0x10000;
	const auto ok = feed([&](const QByteArray &chunk) {
		md5.addData(chunk);
		sha1.addData(chunk);
		sha256.addData(chunk);
		if (head.size() < kHeadSize) {
			head.append(chunk.left(kHeadSize - head.size()));
		}
		result.size += chunk.size();
	});
	if (!ok) {
		return result;
	}
	result.md5 = QString::fromLatin1(md5.result().toHex());
	result.sha1 = QString::fromLatin1(sha1.result().toHex());
	result.sha256 = QString::fromLatin1(sha256.result().toHex());
	result.magicType = DetectMagicType(head, &result.magicExecutable);
	result.ok = true;
	return result;
}

} // namespace

FileHashes ComputeFileHashes(const QString &path) {
	return ComputeHashesWith([&](auto &&add) {
		auto file = QFile(path);
		if (!file.open(QIODevice::ReadOnly)) {
			return false;
		}
		constexpr auto kChunk = 1024 * 1024;
		while (!file.atEnd()) {
			const auto chunk = file.read(kChunk);
			if (chunk.isEmpty() && file.error() != QFile::NoError) {
				return false;
			}
			add(chunk);
		}
		return true;
	});
}

FileHashes ComputeBytesHashes(const QByteArray &bytes) {
	return ComputeHashesWith([&](auto &&add) {
		add(bytes);
		return true;
	});
}

void ApplyContentCheck(FileReport &report, const FileHashes &hashes) {
	if (!hashes.ok || hashes.magicType.isEmpty()) {
		return;
	}
	if (hashes.magicExecutable && !report.executable) {
		report.add(
			Severity::Critical,
			QStringLiteral("Содержимое на самом деле — \"%1\", а имя заканчивается на "
				"\".%2\". Файл замаскирован.").arg(
				hashes.magicType,
				report.realExtension));
	} else if (hashes.magicType.contains(QStringLiteral("JavaScript"))
		|| hashes.magicType.contains(QStringLiteral("запуска"))
		|| hashes.magicType.contains(QStringLiteral("скрипт"))) {
		report.add(
			Severity::High,
			QStringLiteral("Проверка содержимого: %1.").arg(hashes.magicType));
	}
}

namespace {

[[nodiscard]] bool MostlyPrintable(const QString &text) {
	if (text.isEmpty()) {
		return false;
	}
	auto printable = 0;
	for (const auto ch : text) {
		if (ch.isPrint() || ch == '\n' || ch == '\r' || ch == '\t') {
			++printable;
		}
	}
	return printable * 100 >= text.size() * 95
		&& !text.contains(QChar(QChar::ReplacementCharacter));
}

[[nodiscard]] QString PrettyJson(const QByteArray &bytes) {
	const auto document = QJsonDocument::fromJson(bytes);
	return document.isNull()
		? QString::fromUtf8(bytes)
		: QString::fromUtf8(document.toJson(QJsonDocument::Indented));
}

[[nodiscard]] QString HashKind(const QString &value) {
	static const auto hex = QRegularExpression("^[0-9a-fA-F]+$");
	if (value.startsWith(QStringLiteral("$2a$"))
		|| value.startsWith(QStringLiteral("$2b$"))
		|| value.startsWith(QStringLiteral("$2y$"))) {
		return QStringLiteral("bcrypt");
	} else if (value.startsWith(QStringLiteral("$argon2"))) {
		return QStringLiteral("Argon2");
	} else if (value.startsWith(QStringLiteral("$6$"))) {
		return QStringLiteral("SHA-512 crypt (Linux /etc/shadow)");
	} else if (value.startsWith(QStringLiteral("$5$"))) {
		return QStringLiteral("SHA-256 crypt");
	} else if (value.startsWith(QStringLiteral("$1$"))) {
		return QStringLiteral("MD5 crypt");
	} else if (value.startsWith(QStringLiteral("$y$"))) {
		return QStringLiteral("yescrypt");
	} else if (!hex.match(value).hasMatch()) {
		return QString();
	}
	switch (value.size()) {
	case 8: return QStringLiteral("CRC32 / Adler32");
	case 16: return QStringLiteral("MySQL323 / половина LM");
	case 32: return QStringLiteral("MD5, NTLM, MD4 или LM");
	case 40: return QStringLiteral("SHA-1 или RIPEMD-160");
	case 56: return QStringLiteral("SHA-224 / SHA3-224");
	case 64: return QStringLiteral("SHA-256 / SHA3-256 / BLAKE2s");
	case 96: return QStringLiteral("SHA-384 / SHA3-384");
	case 128: return QStringLiteral("SHA-512 / SHA3-512 / BLAKE2b / Whirlpool");
	}
	return QString();
}

} // namespace

std::vector<Decoded> DecodeText(const QString &text) {
	auto result = std::vector<Decoded>();
	const auto value = text.trimmed();
	if (value.isEmpty()) {
		return result;
	}
	if (const auto kind = HashKind(value); !kind.isEmpty()) {
		result.push_back({ QStringLiteral("Тип хеша"), kind });
	}
	const auto parts = value.split('.');
	if (parts.size() == 3 && value.startsWith(QStringLiteral("eyJ"))) {
		const auto decode = [](const QString &part) {
			return QByteArray::fromBase64(
				part.toLatin1(),
				QByteArray::Base64UrlEncoding);
		};
		result.push_back({
			QStringLiteral("JWT заголовок"),
			PrettyJson(decode(parts[0])) });
		auto payload = PrettyJson(decode(parts[1]));
		const auto claims = QJsonDocument::fromJson(
			decode(parts[1])).object();
		for (const auto &claim : { "exp", "iat", "nbf" }) {
			const auto key = QString::fromLatin1(claim);
			if (claims.contains(key)) {
				payload += QStringLiteral("\n%1 = %2").arg(
					key,
					QDateTime::fromSecsSinceEpoch(
						claims.value(key).toInteger(),
						QTimeZone::UTC).toString(Qt::ISODate));
			}
		}
		result.push_back({ QStringLiteral("JWT данные"), payload });
		result.push_back({
			QStringLiteral("JWT подпись"),
			parts[2].isEmpty()
				? QStringLiteral("ОТСУТСТВУЕТ (alg none?)")
				: QStringLiteral("есть, не проверялась") });
		return result;
	}
	static const auto base64 = QRegularExpression(
		"^[A-Za-z0-9+/_-]{8,}={0,2}$");
	if (base64.match(value).hasMatch() && value.size() % 4 != 1) {
		const auto decoded = QByteArray::fromBase64(
			value.toLatin1(),
			value.contains('-') || value.contains('_')
				? QByteArray::Base64UrlEncoding
				: QByteArray::Base64Encoding);
		const auto string = QString::fromUtf8(decoded);
		if (MostlyPrintable(string)) {
			result.push_back({ QStringLiteral("Base64"), string });
		} else if (!decoded.isEmpty()) {
			auto executable = false;
			const auto magic = DetectMagicType(decoded, &executable);
			if (!magic.isEmpty()) {
				result.push_back({
					QStringLiteral("Base64 (двоичные данные)"),
					magic + (executable
						? QStringLiteral(" — ИСПОЛНЯЕМЫЙ КОД!")
						: QString()) });
			}
		}
	}
	static const auto hex = QRegularExpression(
		"^(?:0x)?(?:[0-9a-fA-F]{2}[\\s:]?){4,}$");
	if (hex.match(value).hasMatch() && HashKind(value).isEmpty()) {
		auto clean = value;
		clean.remove(QStringLiteral("0x"));
		clean.remove(QRegularExpression("[\\s:]"));
		const auto decoded = QByteArray::fromHex(clean.toLatin1());
		const auto string = QString::fromUtf8(decoded);
		if (MostlyPrintable(string)) {
			result.push_back({ QStringLiteral("Hex"), string });
		}
	}
	if (value.contains('%')) {
		const auto decoded = QUrl::fromPercentEncoding(value.toUtf8());
		if (decoded != value) {
			result.push_back({ QStringLiteral("URL-кодирование"), decoded });
		}
	}
	const auto refanged = Refang(value);
	if (refanged != value) {
		result.push_back({ QStringLiteral("Восстановленная ссылка"), refanged });
	}
	return result;
}

Report AnalyzeMessageText(const QString &text, bool fromStranger) {
	struct Group {
		const char *name;
		QStringList words;
	};
	static const auto groups = std::vector<Group>{
		{ "обещание приза", {
			"вы выиграли", "поздравляем", "розыгрыш", "ваш приз",
			"победител", "yutdingiz", "yutib oldingiz", "g'olib",
			"sovrin", "you won", "you have won", "giveaway", "winner",
			"ютдингиз", "совға", "ғолиб" } },
		{ "бесплатный Premium / подарок", {
			"premium бесплатно", "бесплатный premium", "telegram premium",
			"tekin premium", "bepul premium", "free premium",
			"подарок от telegram", "sovg'a", "stars бесплатно",
			"бесплатные звёзды", "free stars", "nft подарок" } },
		{ "данные карты / банка", {
			"карта заблокирована", "номер карты", "данные карты", "cvv",
			"срок действия карты", "karta bloklandi", "karta raqam",
			"kartangiz", "card number", "card details", "код из смс",
			"sms kod", "sms-kod", "смс код", "plastik karta" } },
		{ "лёгкий заработок / инвестиции", {
			"пассивный доход", "доход от", "гарантированн", "инвестиц",
			"арбитраж", "заработок без", "daromad", "investitsiya",
			"pul ishlash", "kuniga", "trading", "usdt", "x2 ", "x10",
			"guaranteed profit", "passive income", "kunlik foyda" } },
		{ "срочность / угроза", {
			"срочно", "немедленно", "в течение 24", "последний шанс",
			"будет заблокирован", "заблокирован", "будет удал", "tezda",
			"shoshiling", "bloklandi",
			"zudlik bilan", "o'chiriladi", "bloklanadi", "urgent",
			"immediately", "will be suspended", "will be deleted" } },
		{ "просьба подтвердить данные", {
			"подтвердите", "верификац", "пройдите проверку", "tasdiqlang",
			"tasdiqlash", "verify your", "confirm your", "введите код",
			"kodni yuboring", "send the code", "отправьте код",
			"скажите код" } },
		{ "фейковая работа", {
			"удалённая работа", "удаленная работа", "работа на дому",
			"оплата за отзывы", "ставить лайки", "uyda ishlash",
			"masofaviy ish", "onlayn ish", "work from home",
			"оплата каждый день" } },
		{ "голосование / помощь", {
			"проголосуйте", "проголосуй", "ovoz bering", "ovoz berib",
			"vote for", "помогите проголосовать" } },
		{ "криптовалютная афера", {
			"airdrop", "connect wallet", "подключите кошелёк",
			"подключите кошелек", "seed", "мнемоническ", "seed-фраз",
			"claim your", "claim now", "drainer" } },
	};
	auto result = Report();
	const auto lowered = text.toLower();
	auto matched = QStringList();
	for (const auto &group : groups) {
		for (const auto &word : group.words) {
			if (lowered.contains(word)) {
				matched.push_back(QString::fromUtf8(group.name));
				break;
			}
		}
	}
	const auto iocs = ExtractIocs(text);
	const auto hasLink = std::any_of(iocs.begin(), iocs.end(), [](
			const Ioc &ioc) {
		return ioc.type == IocType::Url || ioc.type == IocType::Domain;
	});
	auto riskyLink = false;
	for (const auto &ioc : iocs) {
		if (ioc.type == IocType::Url
			&& AnalyzeUrl(ioc.value).atLeast(Severity::High)) {
			riskyLink = true;
		}
	}
	const auto score = matched.size()
		+ (hasLink ? 1 : 0)
		+ (riskyLink ? 2 : 0)
		+ (fromStranger ? 1 : 0);
	if (matched.isEmpty() && !riskyLink) {
		return result;
	}
	const auto severity = (score >= 5)
		? Severity::Critical
		: (score >= 4)
		? Severity::High
		: (score >= 3)
		? Severity::Warning
		: Severity::Notice;
	auto reasons = matched;
	if (riskyLink) {
		reasons.push_back(QStringLiteral("опасная ссылка"));
	} else if (hasLink) {
		reasons.push_back(QStringLiteral("ссылка"));
	}
	if (fromStranger) {
		reasons.push_back(QStringLiteral("от незнакомца"));
	}
	result.add(
		severity,
		QStringLiteral("Признаки мошенничества: %1.").arg(
			reasons.join(QStringLiteral(", "))));
	return result;
}

Report AnalyzePeer(const PeerFacts &facts) {
	auto result = Report();
	if (facts.scam) {
		result.add(
			Severity::Critical,
			QStringLiteral("Telegram пометил этот аккаунт как SCAM (мошенник)."));
	}
	if (facts.fake) {
		result.add(
			Severity::Critical,
			QStringLiteral("Telegram пометил этот аккаунт как FAKE (выдаёт себя за "
				"другого)."));
	}
	if (facts.verified) {
		return result;
	}
	constexpr auto kTelegramServiceId = 777000;
	const auto lowered = (facts.name + ' ' + facts.username).toLower();
	static const auto authority = QStringList{
		"telegram", "support", "admin", "official", "security",
		"notification", "moderator", "durov", "service", "verify",
		"help desk", "helpdesk", "customer care", "bank",
	};
	auto matched = QStringList();
	for (const auto &word : authority) {
		if (lowered.contains(word)) {
			matched.push_back(word);
		}
	}
	if (!matched.isEmpty() && facts.userId != kTelegramServiceId) {
		result.add(
			facts.contact ? Severity::Notice : Severity::High,
			QStringLiteral("Имя претендует на официальность (%1), но аккаунт не "
				"верифицирован. Настоящие уведомления Telegram приходят "
				"только от верифицированного аккаунта \"Telegram\" (ID "
				"777000).").arg(matched.join(QStringLiteral(", "))));
	}
	auto mixed = false;
	for (const auto &word : facts.name.split(' ', Qt::SkipEmptyParts)) {
		const auto info = Scripts(word);
		if (int(info.latin) + int(info.cyrillic) + int(info.greek) > 1) {
			mixed = true;
		}
	}
	if (mixed) {
		result.add(
			Severity::Warning,
			QStringLiteral("Имя смешивает латиницу и кириллицу/греческие буквы в одном "
				"слове — частый приём подделки."));
	}
	auto invisible = false;
	for (const auto ch : facts.name.toUcs4()) {
		if (IsBidiControl(ch) || IsZeroWidth(ch)) {
			invisible = true;
		}
	}
	if (invisible) {
		result.add(
			Severity::Warning,
			QStringLiteral("Имя содержит невидимые символы или символы управления "
				"направлением."));
	}
	if (facts.userId && !facts.contact && facts.username.isEmpty()
		&& !facts.bot) {
		result.add(
			Severity::Info,
			QStringLiteral("Нет в ваших контактах и нет имени пользователя."));
	}
	return result;
}

QString VirusTotalHashUrl(const QString &sha256) {
	return QStringLiteral("https://www.virustotal.com/gui/file/") + sha256;
}

std::vector<LookupLink> LookupLinks(const Ioc &ioc) {
	const auto v = QString::fromLatin1(QUrl::toPercentEncoding(ioc.value));
	const auto link = [](const char *service, QString url) {
		return LookupLink{ QString::fromLatin1(service), std::move(url) };
	};
	switch (ioc.type) {
	case IocType::IPv4:
	case IocType::IPv6: return {
		link("VirusTotal", "https://www.virustotal.com/gui/ip-address/" + v),
		link("AbuseIPDB", "https://www.abuseipdb.com/check/" + v),
		link("Shodan", "https://www.shodan.io/host/" + v),
		link("GreyNoise", "https://viz.greynoise.io/ip/" + v),
		link("OTX", "https://otx.alienvault.com/indicator/ip/" + v),
	};
	case IocType::Domain: return {
		link("VirusTotal", "https://www.virustotal.com/gui/domain/" + v),
		link("urlscan", "https://urlscan.io/domain/" + v),
		link("OTX", "https://otx.alienvault.com/indicator/domain/" + v),
		link("crt.sh", "https://crt.sh/?q=" + v),
		link("WHOIS", "https://who.is/whois/" + v),
	};
	case IocType::Url: {
		const auto id = QString::fromLatin1(QCryptographicHash::hash(
			ioc.value.toUtf8(),
			QCryptographicHash::Sha256).toHex());
		return {
			link("VirusTotal", "https://www.virustotal.com/gui/url/" + id),
			link("urlscan", "https://urlscan.io/search/#page.url:%22"
				+ v + "%22"),
			link("URLhaus", "https://urlhaus.abuse.ch/browse.php?search="
				+ v),
		};
	}
	case IocType::MD5:
	case IocType::SHA1:
	case IocType::SHA256:
	case IocType::SHA512: return {
		link("VirusTotal", "https://www.virustotal.com/gui/file/" + v),
		link("MalwareBazaar", "https://bazaar.abuse.ch/browse.php?search="
			+ QString::fromLatin1(QUrl::toPercentEncoding(
				(ioc.type == IocType::MD5 ? "md5:" : ioc.type == IocType::SHA1
					? "sha1:" : "sha256:") + ioc.value))),
		link("OTX", "https://otx.alienvault.com/indicator/file/" + v),
	};
	case IocType::CVE: return {
		link("NVD", "https://nvd.nist.gov/vuln/detail/" + v),
		link("CVE.org", "https://www.cve.org/CVERecord?id=" + v),
		link("Exploit-DB", "https://www.exploit-db.com/search?cve="
			+ v.mid(4)),
	};
	case IocType::MitreAttack: {
		auto path = ioc.value;
		path.replace('.', '/');
		return {
			link("MITRE ATT&CK", (ioc.value.startsWith("TA")
				? "https://attack.mitre.org/tactics/"
				: "https://attack.mitre.org/techniques/") + path + '/'),
		};
	}
	case IocType::Bitcoin: return {
		link("Blockchair", "https://blockchair.com/bitcoin/address/" + v),
		link("mempool", "https://mempool.space/address/" + v),
	};
	case IocType::Ethereum: return {
		link("Etherscan", "https://etherscan.io/address/" + v),
	};
	case IocType::Ton: return {
		link("Tonviewer", "https://tonviewer.com/" + v),
		link("Tonscan", "https://tonscan.org/address/" + v),
	};
	case IocType::Email: return {
		link("Have I Been Pwned", "https://haveibeenpwned.com/"),
	};
	case IocType::TelegramUsername: {
		const auto name = QString(v).remove(QStringLiteral("%40"));
		return {
			link("Telegram", "https://t.me/" + name),
			link("GitHub", "https://github.com/" + name),
			link("Instagram", "https://www.instagram.com/" + name + '/'),
			link("X", "https://x.com/" + name),
			link("TikTok", "https://www.tiktok.com/@" + name),
			link("WhatsMyName", "https://whatsmyname.app/?q=" + name),
		};
	}
	default: return {};
	}
}

namespace {

[[nodiscard]] int ReadExifOrientation(const QByteArray &segment) {
	// segment: "Exif\0\0" + TIFF.
	const auto tiff = segment.mid(6);
	if (tiff.size() < 8) {
		return 0;
	}
	const auto big = (tiff[0] == 'M');
	const auto u16 = [&](int at) -> int {
		if (at + 2 > tiff.size()) {
			return -1;
		}
		const auto a = uchar(tiff[at]), b = uchar(tiff[at + 1]);
		return big ? ((a << 8) | b) : ((b << 8) | a);
	};
	const auto u32 = [&](int at) -> qint64 {
		if (at + 4 > tiff.size()) {
			return -1;
		}
		const auto hi = u16(big ? at : at + 2);
		const auto lo = u16(big ? at + 2 : at);
		return (qint64(hi) << 16) | lo;
	};
	const auto ifd = u32(4);
	if (ifd < 8 || ifd >= tiff.size()) {
		return 0;
	}
	const auto count = u16(int(ifd));
	for (auto i = 0; i < count; ++i) {
		const auto entry = int(ifd) + 2 + i * 12;
		if (u16(entry) == 0x0112) {
			const auto value = u16(entry + 8);
			return (value >= 1 && value <= 8) ? value : 0;
		}
	}
	return 0;
}

[[nodiscard]] QByteArray MinimalExif(int orientation) {
	auto result = QByteArray("Exif\0\0MM\0\x2A\0\0\0\x08", 14);
	result.append(char(0)).append(char(1)); // One entry.
	result.append(char(0x01)).append(char(0x12)); // Orientation.
	result.append(char(0)).append(char(3)); // SHORT.
	result.append(QByteArray("\0\0\0\x01", 4)); // Count.
	result.append(char(0)).append(char(orientation)).append(2, char(0));
	result.append(QByteArray(4, char(0))); // No next IFD.
	return result;
}

[[nodiscard]] QByteArray StripJpeg(const QByteArray &bytes, bool *changed) {
	auto result = QByteArray("\xFF\xD8", 2);
	auto at = 2;
	auto orientation = 0;
	auto removed = false;
	while (at + 4 <= bytes.size()) {
		if (uchar(bytes[at]) != 0xFF) {
			return bytes; // Broken structure, don't touch.
		}
		const auto marker = uchar(bytes[at + 1]);
		if (marker == 0xFF) {
			++at; // Fill byte.
			continue;
		} else if (marker == 0xDA || marker == 0xD9) {
			// Start of scan: the rest is image data.
			if (orientation > 1) {
				const auto exif = MinimalExif(orientation);
				const auto length = exif.size() + 2;
				auto header = QByteArray("\xFF\xE1", 2);
				header.append(char(length >> 8)).append(char(length & 0xFF));
				result.insert(2, header + exif);
			}
			result.append(bytes.mid(at));
			if (changed) {
				*changed = removed;
			}
			return removed ? result : bytes;
		}
		const auto length = (uchar(bytes[at + 2]) << 8) | uchar(bytes[at + 3]);
		if (length < 2 || at + 2 + length > bytes.size()) {
			return bytes;
		}
		const auto segment = bytes.mid(at + 4, length - 2);
		const auto drop = (marker == 0xE1) // EXIF / XMP
			|| (marker == 0xED) // IPTC / Photoshop
			|| (marker == 0xFE); // Comment
		if (marker == 0xE1 && segment.startsWith(QByteArray("Exif\0", 5))) {
			orientation = ReadExifOrientation(segment);
		}
		if (drop) {
			removed = true;
		} else {
			result.append(bytes.mid(at, 2 + length));
		}
		at += 2 + length;
	}
	return bytes;
}

[[nodiscard]] QByteArray StripPng(const QByteArray &bytes, bool *changed) {
	auto result = bytes.left(8);
	auto at = 8;
	auto removed = false;
	while (at + 12 <= bytes.size()) {
		const auto length = (qint64(uchar(bytes[at])) << 24)
			| (uchar(bytes[at + 1]) << 16)
			| (uchar(bytes[at + 2]) << 8)
			| uchar(bytes[at + 3]);
		if (at + 12 + length > bytes.size()) {
			return bytes;
		}
		const auto type = bytes.mid(at + 4, 4);
		const auto drop = (type == "eXIf")
			|| (type == "tEXt")
			|| (type == "zTXt")
			|| (type == "iTXt")
			|| (type == "tIME");
		if (drop) {
			removed = true;
		} else {
			result.append(bytes.mid(at, 12 + length));
		}
		at += 12 + int(length);
		if (type == "IEND") {
			break;
		}
	}
	if (changed) {
		*changed = removed;
	}
	return removed ? result : bytes;
}

} // namespace

namespace {

[[nodiscard]] quint64 BoxSize(const QByteArray &b, qint64 at, int *header) {
	const auto u32 = [&](qint64 p) {
		const auto d = reinterpret_cast<const uchar*>(b.constData() + p);
		return (quint64(d[0]) << 24) | (d[1] << 16) | (d[2] << 8) | d[3];
	};
	*header = 8;
	auto size = u32(at);
	if (size == 1 && at + 16 <= b.size()) {
		size = (u32(at + 8) << 32) | u32(at + 12);
		*header = 16;
	} else if (size == 0) {
		size = b.size() - at;
	}
	return size;
}

bool FreeMetadataBoxes(QByteArray &b, qint64 from, qint64 till, int depth) {
	static const auto containers = QSet<QByteArray>{
		"moov", "trak", "mdia", "minf", "stbl", "edts", "dinf",
	};
	auto changed = false;
	auto at = from;
	while (at + 8 <= till && depth < 8) {
		auto header = 0;
		const auto size = BoxSize(b, at, &header);
		if (size < quint64(header) || at + qint64(size) > till) {
			break;
		}
		const auto type = b.mid(at + 4, 4);
		if (type == "udta" || type == "meta" || type == "uuid") {
			// "uuid" boxes carry XMP in many cameras.
			b.replace(at + 4, 4, "free");
			std::fill(
				b.begin() + at + header,
				b.begin() + at + qint64(size),
				char(0));
			changed = true;
		} else if (containers.contains(type)) {
			changed |= FreeMetadataBoxes(
				b,
				at + header,
				at + qint64(size),
				depth + 1);
		}
		at += qint64(size);
	}
	return changed;
}

} // namespace

QByteArray StripVideoMetadata(QByteArray bytes, bool *changed) {
	const auto isMp4 = bytes.size() > 12 && bytes.mid(4, 4) == "ftyp";
	const auto result = isMp4
		&& FreeMetadataBoxes(bytes, 0, bytes.size(), 0);
	if (changed) {
		*changed = result;
	}
	return bytes;
}

QByteArray StripImageMetadata(const QByteArray &bytes, bool *changed) {
	if (changed) {
		*changed = false;
	}
	if (bytes.startsWith(QByteArray("\xFF\xD8", 2))) {
		return StripJpeg(bytes, changed);
	} else if (bytes.startsWith(QByteArray("\x89PNG\r\n\x1A\n", 8))) {
		return StripPng(bytes, changed);
	}
	return bytes;
}

} // namespace SecGram
