#include "secgram/secgram_analyzer.h"
#include <cstdio>
using namespace SecGram;
static void url(const char *u) {
	const auto r = AnalyzeUrl(QString::fromUtf8(u));
	printf("\n== %s  [%s] host=%s reg=%s\n", u, qPrintable(SeverityName(r.maxSeverity())), qPrintable(r.host), qPrintable(r.registrableDomain));
	for (auto &f : r.findings) printf("   %-8s %s\n", qPrintable(SeverityName(f.severity)), qPrintable(f.text));
	if (r.cleanUrl != QString::fromUtf8(u)) printf("   clean: %s\n", qPrintable(r.cleanUrl));
}
static void file(const char *n, const char *mime = "") {
	const auto r = AnalyzeFileName(QString::fromUtf8(n), mime);
	printf("\n== file %s -> %s [%s] exec=%d\n", qPrintable(r.displayName), qPrintable(r.realExtension), qPrintable(SeverityName(r.maxSeverity())), r.executable);
	for (auto &f : r.findings) printf("   %-8s %s\n", qPrintable(SeverityName(f.severity)), qPrintable(f.text));
}
int main() {
	url("https://telegram.org/apps");
	url("https://t.me/durov");
	url("https://telegram-premium-gift.xyz/login?utm_source=tg&ref=1");
	url("https://teIegram.org/verify");
	url("https://xn--telegrm-4fg.org/");
	url("https://аррӏе.com/");
	url("http://google.com@evil.example/path");
	url("http://192.168.1.1/admin");
	url("http://3232235777/");
	url("https://bit.ly/3abcd");
	url("https://evil.pages.dev/wallet/connect");
	url("https://example.com/download/setup.exe");
	url("https://www.google.com/url?q=https://phish.top/login");
	url("https://www.youtube.com/watch?v=abc&si=XYZ&t=10");
	url("javascript:alert(1)");
	url("https://paypa1-secure.com/signin");
	url("https://kapitalbank.uz/uz/");
	url("https://kapltalbank-uz.com/");
	file("invoice.pdf.exe");
	file("photo\u202Egpj.exe");
	file("document.docm");
	file("report.pdf");
	file("app.apk");
	file("image.jpg", "application/x-msdownload");
	file("readme                  .scr");
	const auto text = QString::fromUtf8(
		"C2 at hxxps://evil-c2[.]top/gate.php and 45.33.32.156, also bad[.]example[.]com. "
		"Contact admin@corp.uz. Hash 44d88612fea8a8f36de82e1278abb02f and "
		"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f; CVE-2024-3094 T1566.001 "
		"wallet bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq 0x52908400098527886E0F7030069857D2E4169EE7 "
		"user @durov_bot path C:\\Users\\bob\\AppData\\evil.exe HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
		"ipv6 2001:db8::1 mac aa:bb:cc:dd:ee:ff time 12:30:45 file main.py and README.md see 1.2.3");
	const auto iocs = ExtractIocs(text);
	printf("\n%s", qPrintable(FormatIocs(iocs, IocFormat::Text, true)));
	printf("\nDEFANG: %s\n", qPrintable(DefangText(QString::fromUtf8("visit https://evil.com/x and 8.8.8.8 or mail a@b.org"))));
	printf("REFANG: %s\n", qPrintable(Refang(QString::fromUtf8("hxxps[://]evil[.]com and 1[.]1[.]1[.]1"))));
	printf("%s\n", qPrintable(FormatIocs(std::vector<Ioc>(iocs.begin(), iocs.begin()+2), IocFormat::Json, false)));
	auto h = ComputeBytesHashes(QByteArray("MZ\x90\x00 test", 9));
	printf("magic=%s exec=%d sha256=%s\n", qPrintable(h.magicType), h.magicExecutable, qPrintable(h.sha256));
	auto fr = AnalyzeFileName("cute_cat.jpg"); ApplyContentCheck(fr, h);
	for (auto &f : fr.findings) printf("   %-8s %s\n", qPrintable(SeverityName(f.severity)), qPrintable(f.text));
}

// Peer checks, appended.
static int peerChecks = [] {
	auto p = PeerFacts{ .name = QString::fromUtf8("Telegram Suppоrt"), .userId = 123456 };
	auto r = AnalyzePeer(p);
	printf("\n== peer %s [%s]\n", qPrintable(p.name), qPrintable(SeverityName(r.maxSeverity())));
	for (auto &f : r.findings) printf("   %-8s %s\n", qPrintable(SeverityName(f.severity)), qPrintable(f.text));
	p = PeerFacts{ .name = "Telegram", .userId = 777000, .verified = true };
	r = AnalyzePeer(p);
	printf("== peer official findings=%d\n", int(r.findings.size()));
	return 0;
}();

static int scamChecks = [] {
	const char *texts[] = {
		"Поздравляем! Вы выиграли Telegram Premium бесплатно, подтвердите по ссылке https://telegram-gift.xyz/claim срочно",
		"Assalomu alaykum, kartangiz bloklandi. Tasdiqlash uchun SMS kodni yuboring",
		"Привет, как дела? Завтра встреча в 10",
	};
	for (auto t : texts) {
		const auto r = AnalyzeMessageText(QString::fromUtf8(t), true);
		printf("\n== scam [%s] %s\n", qPrintable(SeverityName(r.maxSeverity())), t);
		for (auto &f : r.findings) printf("   %s\n", qPrintable(f.text));
	}
	return 0;
}();

static int decodeChecks = [] {
	for (auto t : { "aGVsbG8gZnJvbSBiYXNlNjQ=", "48656c6c6f20776f726c64", "5f4dcc3b5aa765d61d8327deb882cf99", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTcwMDAwMDAwMH0.", "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA=", "%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82" }) {
		printf("\n== decode %s\n", t);
		for (auto &d : DecodeText(QString::fromUtf8(t))) printf("   [%s] %s\n", qPrintable(d.kind), qPrintable(d.value));
	}
	printf("\n== onion: %s\n", qPrintable(AnalyzeUrl("http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/").findings.back().text));
	return 0;
}();

static int stixChecks = [] {
	const auto iocs = ExtractIocs("evil.top 1.2.3.4 44d88612fea8a8f36de82e1278abb02f CVE-2024-3094 @scammer_bot");
	const auto stix = FormatIocs(iocs, IocFormat::Stix, false);
	const auto misp = FormatIocs(iocs, IocFormat::Misp, false);
	printf("\n== stix objects=%d misp attrs=%d\n", int(stix.count("\"type\": \"indicator\"") + stix.count("\"type\": \"vulnerability\"")), int(misp.count("\"category\"")));
	for (auto &ioc : iocs) if (ioc.type == IocType::TelegramUsername) printf("== username links=%d\n", int(LookupLinks(ioc).size()));
	return 0;
}();
