/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "secgram/secgram_ui.h"

#include "secgram/secgram_updater.h"

#include "secgram/secgram_account.h"

#include "secgram/secgram_files.h"
#include "secgram/secgram_people.h"
#include "secgram/secgram_tools.h"
#include "secgram/secgram_crypto.h"
#include "dialogs/dialogs_indexed_list.h"
#include "dialogs/dialogs_row.h"
#include "secgram/secgram_net.h"
#include "main/main_account.h"
#include "main/main_domain.h"
#include "storage/storage_domain.h"

#include "apiwrap.h"
#include "base/options.h"
#include "base/unixtime.h"
#include "core/application.h"
#include "core/click_handler_types.h"
#include "core/file_utilities.h"
#include "data/data_document.h"
#include "data/data_media_types.h"
#include "data/data_peer.h"
#include "data/data_session.h"
#include "data/data_user.h"
#include "data/data_web_page.h"
#include "data/data_channel.h"
#include "history/history.h"
#include "history/history_item.h"
#include "history/history_item_components.h"
#include "history/history_item_reply_markup.h"
#include "history/view/history_view_context_menu.h"
#include "history/view/history_view_list_widget.h"
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "secgram/secgram_history_log.h"
#include "secgram/secgram_intel.h"
#include "secgram/secgram_account.h"
#include "settings/settings_common.h"
#include "ui/layers/generic_box.h"
#include "ui/vertical_list.h"
#include "ui/widgets/buttons.h"
#include "ui/layers/show.h"
#include "ui/text/text_utilities.h"
#include "ui/toast/toast.h"
#include "ui/widgets/labels.h"
#include "ui/widgets/popup_menu.h"
#include "window/window_controller.h"
#include "window/window_session_controller.h"

#include "styles/style_layers.h"
#include "styles/style_settings.h"
#include "styles/style_menu_icons.h"
#include "styles/style_widgets.h"

#include <QtCore/QFileInfo>
#include <QtCore/QDir>
#include <QtCore/QRegularExpression>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QStandardPaths>
#include <QtGui/QClipboard>
#include <QtGui/QGuiApplication>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtWidgets/QApplication>
#include <QtCore/QTimer>
#include <QtGui/QKeyEvent>

namespace SecGram {
namespace {

base::options::toggle LinkGuard({
	.id = kOptionLinkGuard,
	.name = "Проверка ссылок",
	.description = "Анализировать каждую внешнюю ссылку перед открытием "
		"(гомоглифы, тайпсквоттинг, IP-адреса, сокращатели, "
		"перенаправления, скачивание исполняемых файлов) и "
		"предупреждать об опасных.",
	.defaultValue = true,
});

base::options::toggle ConfirmAllLinks({
	.id = kOptionConfirmAllLinks,
	.name = "Подтверждать каждую ссылку",
	.description = "Всегда показывать анализ перед открытием любой внешней "
		"ссылки, даже безопасной на вид.",
});

base::options::toggle StripTrackingOption({
	.id = kOptionStripTracking,
	.name = "Удалять трекеры из ссылок",
	.description = "Удалять utm_*, fbclid, gclid и другие параметры слежки "
		"из ссылок перед открытием.",
	.defaultValue = true,
});

base::options::toggle FileGuard({
	.id = kOptionFileGuard,
	.name = "Проверка файлов",
	.description = "Проверять имя и содержимое скачанных файлов перед "
		"открытием: RTLO, двойные расширения, программы под "
		"видом документов, макросы.",
	.defaultValue = true,
});

base::options::toggle ContextTools({
	.id = kOptionContextTools,
	.name = "Раздел SecGram в меню сообщения",
	.description = "Показывать подменю SecGram (информация и ID, извлечение "
		"IOC, обезвреживание, проверка ссылок и файлов) в "
		"контекстном меню сообщения.",
	.defaultValue = true,
});

base::options::toggle GhostReadOption({
	.id = kOptionGhostRead,
	.name = "Не отправлять отметку о прочтении",
	.description = "Читать сообщения так, чтобы отправитель не видел "
		"двойную галочку. Если вы напишете в чат, сообщения всё "
		"равно станут прочитанными.",
});

base::options::toggle GhostTypingOption({
	.id = kOptionGhostTyping,
	.name = "Скрывать статус «печатает…»",
	.description = "Не отправлять статусы «печатает», «записывает» и "
		"«отправляет файл».",
});

base::options::toggle GhostOnlineOption({
	.id = kOptionGhostOnline,
	.name = "Всегда оффлайн",
	.description = "Никогда не сообщать статус «в сети». При отправке "
		"сообщения вы можете на мгновение появиться в сети.",
});

base::options::toggle ScamDetectorOption({
	.id = kOptionScamDetector,
	.name = "Детектор мошенничества",
	.description = "Предупреждать о входящих сообщениях с признаками "
		"мошенничества (призы, «бесплатный Premium», блокировка карты, "
		"инвестиции, просьба кода) и проверять ссылки от незнакомцев.",
	.defaultValue = true,
});

base::options::toggle BlockExecutablesOption({
	.id = kOptionBlockExecutables,
	.name = "Запретить запуск программ",
	.description = "Не давать открывать исполняемые файлы и скрипты "
		"(.exe, .apk, .bat, .js…) из чатов — только показать в папке.",
});

base::options::toggle NoRiskyAutoDownloadOption({
	.id = kOptionNoRiskyAutoDownload,
	.name = "Не скачивать опасные файлы автоматически",
	.description = "Автозагрузка никогда не скачивает исполняемые файлы, "
		"скрипты, макросы и замаскированные файлы.",
	.defaultValue = true,
});

base::options::toggle ShowSecondsOption({
	.id = kOptionShowSeconds,
	.name = "Время с секундами",
	.description = "Показывать время сообщений с секундами (12:34:56).",
	.restartRequired = true,
});

base::options::toggle ConfirmRevokeOption({
	.id = kOptionConfirmRevoke,
	.name = "Подтверждать удаление у всех",
	.description = "Дополнительно спрашивать перед удалением сообщений "
		"у собеседника — это нельзя отменить.",
	.defaultValue = true,
});

base::options::toggle GhostStoriesOption({
	.id = kOptionGhostStories,
	.name = "Ghost mode: незаметный просмотр историй",
	.description = "Не сообщать автору, что вы посмотрели его историю.",
});

base::options::toggle GhostMediaOption({
	.id = kOptionGhostMedia,
	.name = "Ghost mode: не отмечать голосовые прослушанными",
	.description = "Собеседник не увидит, что вы прослушали голосовое или "
		"посмотрели видеосообщение.",
});

base::options::toggle HidePhoneOption({
	.id = kOptionHidePhone,
	.name = "Скрывать свой номер на экране",
	.description = "Маскировать ваш номер телефона в интерфейсе — удобно "
		"при демонстрации экрана и записи видео.",
});

base::options::toggle PanicOption({
	.id = kOptionPanic,
	.name = "Кнопка паники (Ctrl+Alt+P)",
	.description = "Мгновенно заблокировать SecGram код-паролем (или "
		"свернуть окно, если пароля нет) и очистить буфер обмена.",
	.defaultValue = true,
});

base::options::toggle ClipboardGuardOption({
	.id = kOptionClipboardGuard,
	.name = "Очищать буфер от кода входа",
	.description = "Если вы скопировали код входа Telegram, буфер обмена "
		"очищается через 30 секунд.",
	.defaultValue = true,
});

base::options::toggle NoLinkPreviewsOption({
	.id = kOptionNoLinkPreviews,
	.name = "Отправлять ссылки без превью",
	.description = "Не прикреплять превью к отправляемым ссылкам — "
		"собеседник не увидит заголовок и картинку сайта.",
});

base::options::toggle StripMetadataOption({
	.id = kOptionStripMetadata,
	.name = "Удалять метаданные фото",
	.description = "Удалять EXIF (GPS-координаты, камера, серийные номера), "
		"XMP и комментарии из JPEG и PNG, отправленных файлом.",
	.defaultValue = true,
});

[[nodiscard]] QString SeverityMark(Severity severity) {
	switch (severity) {
	case Severity::Info: return QString::fromUtf8("\xE2\x9A\xAA"); // ⚪
	case Severity::Notice: return QString::fromUtf8("\xF0\x9F\x94\xB5"); // 🔵
	case Severity::Warning: return QString::fromUtf8("\xF0\x9F\x9F\xA1"); // 🟡
	case Severity::High: return QString::fromUtf8("\xF0\x9F\x9F\xA0"); // 🟠
	case Severity::Critical: return QString::fromUtf8("\xF0\x9F\x94\xB4"); // 🔴
	}
	return QString();
}

[[nodiscard]] QString Verdict(const Report &report) {
	if (report.findings.empty() || !report.atLeast(Severity::Notice)) {
		return u"Известных угроз не найдено"_q;
	}
	const auto severity = report.maxSeverity();
	return SeverityMark(severity)
		+ u"Риск: "_q
		+ SeverityName(severity);
}

void CopyWithToast(
		const QString &text,
		const QString &toast,
		std::shared_ptr<Ui::Show> show = nullptr) {
	QGuiApplication::clipboard()->setText(text);
	if (show) {
		show->showToast(toast);
	}
}

[[nodiscard]] std::shared_ptr<Ui::Show> ShowFromContext(
		const QVariant &context) {
	const auto my = context.value<ClickHandlerContext>();
	if (my.show) {
		return my.show;
	} else if (const auto controller = my.sessionWindow.get()) {
		return controller->uiShow();
	} else if (const auto window = Core::App().activeWindow()) {
		return window->uiShow();
	}
	return nullptr;
}

not_null<Ui::FlatLabel*> AddLabel(
		not_null<Ui::GenericBox*> box,
		TextWithEntities text,
		const style::FlatLabel &st = st::boxLabel) {
	const auto label = box->addRow(
		object_ptr<Ui::FlatLabel>(box, rpl::single(std::move(text)), st));
	label->setSelectable(true);
	return label;
}

void AddFindings(
		not_null<Ui::GenericBox*> box,
		const Report &report,
		const style::FlatLabel &st) {
	for (const auto &finding : report.findings) {
		box->addSkip(st::boxLittleSkip);
		AddLabel(
			box,
			TextWithEntities{ SeverityMark(finding.severity) + ' ' }.append(
				Ui::Text::Bold(SeverityName(finding.severity) + u": "_q)
			).append(finding.text),
			st);
	}
}

[[nodiscard]] QString BotApiId(not_null<PeerData*> peer) {
	const auto id = peer->id;
	if (peerIsUser(id)) {
		return QString::number(peerToUser(id).bare);
	} else if (peerIsChat(id)) {
		return '-' + QString::number(peerToChat(id).bare);
	}
	return u"-100"_q + QString::number(peerToChannel(id).bare);
}

[[nodiscard]] QString FormatDate(TimeId date) {
	if (!date) {
		return QString();
	}
	const auto local = base::unixtime::parse(date);
	return local.toString(u"yyyy-MM-dd HH:mm:ss"_q)
		+ u" (UTC "_q
		+ local.toUTC().toString(u"yyyy-MM-dd HH:mm:ss"_q)
		+ ')';
}

[[nodiscard]] QString FormatSize(qint64 size) {
	return QLocale::system().formattedDataSize(size)
		+ u"(%1 байт)"_q.arg(size);
}

[[nodiscard]] QJsonObject PeerJson(not_null<PeerData*> peer) {
	auto result = QJsonObject{
		{ u"id"_q, BotApiId(peer) },
		{ u"name"_q, peer->name() },
	};
	if (const auto username = peer->username(); !username.isEmpty()) {
		result.insert(u"username"_q, '@' + username);
	}
	if (const auto user = peer->asUser()) {
		if (!user->phone().isEmpty()) {
			result.insert(u"phone"_q, '+' + user->phone());
		}
		if (user->isBot()) {
			result.insert(u"bot"_q, true);
		}
	}
	if (peer->isVerified()) {
		result.insert(u"verified"_q, true);
	}
	if (peer->isScam()) {
		result.insert(u"scam"_q, true);
	}
	if (peer->isFake()) {
		result.insert(u"fake"_q, true);
	}
	return result;
}

[[nodiscard]] QString PeerLine(not_null<PeerData*> peer) {
	auto result = peer->name() + u"  [id "_q + BotApiId(peer) + ']';
	if (const auto username = peer->username(); !username.isEmpty()) {
		result += u"  @"_q + username;
	}
	if (peer->isScam()) {
		result += u"  ⚠ SCAM"_q;
	} else if (peer->isFake()) {
		result += u"  ⚠ FAKE"_q;
	} else if (peer->isVerified()) {
		result += u"✔ верифицирован"_q;
	}
	return result;
}

void ApplyFeeds(UrlReport &report, const QString &url) {
	const auto source = ThreatFeedMatch(url);
	if (!source.isEmpty()) {
		report.add(
			Severity::Critical,
			u"Адрес есть в базе опасных сайтов %1."_q.arg(source));
	}
}

[[nodiscard]] Report PeerRisk(not_null<PeerData*> peer) {
	auto facts = PeerFacts{
		.name = peer->name(),
		.username = peer->username(),
		.verified = peer->isVerified(),
		.scam = peer->isScam(),
		.fake = peer->isFake(),
	};
	if (const auto user = peer->asUser()) {
		facts.userId = peerToUser(peer->id).bare;
		facts.contact = user->isContact();
		facts.bot = user->isBot();
	}
	auto result = AnalyzePeer(facts);
	const auto user = peer->asUser();
	if (user && !user->isContact() && !user->isSelf()) {
		const auto name = peer->name().trimmed().toLower();
		for (const auto &row : peer->owner().contactsList()->all()) {
			const auto history = row->history();
			const auto contact = history ? history->peer.get() : nullptr;
			if (contact
				&& contact != peer
				&& contact->name().trimmed().toLower() == name) {
				result.add(
					Severity::High,
					u"Имя совпадает с вашим контактом «%1», но это ДРУГОЙ "
						"аккаунт (ID %2, у контакта %3). Классическая "
						"подмена знакомого."_q.arg(
							contact->name(),
							BotApiId(peer),
							BotApiId(contact)));
				break;
			}
		}
	}
	return result;
}

[[nodiscard]] QString CollectText(
		not_null<HistoryView::ListWidget*> list,
		const HistoryView::ContextMenuRequest &request) {
	if (!request.selectedText.rich.text.isEmpty()) {
		return request.selectedText.rich.text;
	}
	auto &owner = list->controller()->session().data();
	auto result = QStringList();
	if (request.overSelection && !request.selectedItems.empty()) {
		for (const auto &selected : request.selectedItems) {
			if (const auto item = owner.message(selected.msgId)) {
				result.push_back(item->originalText().text);
			}
		}
	} else if (const auto item = request.item) {
		result.push_back(item->originalText().text);
		if (const auto media = item->media()) {
			if (const auto document = media->document()) {
				result.push_back(document->filename());
			}
		}
	}
	return result.join('\n');
}

} // namespace

const char kOptionLinkGuard[] = "secgram-link-guard";
const char kOptionConfirmAllLinks[] = "secgram-confirm-all-links";
const char kOptionStripTracking[] = "secgram-strip-tracking";
const char kOptionFileGuard[] = "secgram-file-guard";
const char kOptionContextTools[] = "secgram-context-tools";
const char kOptionGhostRead[] = "secgram-ghost-read";
const char kOptionGhostTyping[] = "secgram-ghost-typing";
const char kOptionGhostOnline[] = "secgram-ghost-online";
const char kOptionStripMetadata[] = "secgram-strip-metadata";
const char kOptionScamDetector[] = "secgram-scam-detector";
const char kOptionBlockExecutables[] = "secgram-block-executables";
const char kOptionNoRiskyAutoDownload[] = "secgram-no-risky-autodownload";
const char kOptionShowSeconds[] = "secgram-show-seconds";
const char kOptionConfirmRevoke[] = "secgram-confirm-revoke";
const char kOptionGhostStories[] = "secgram-ghost-stories";
const char kOptionGhostMedia[] = "secgram-ghost-media";
const char kOptionHidePhone[] = "secgram-hide-phone";
const char kOptionPanic[] = "secgram-panic";
const char kOptionClipboardGuard[] = "secgram-clipboard-guard";
const char kOptionNoLinkPreviews[] = "secgram-no-link-previews";

bool NoLinkPreviews() {
	return NoLinkPreviewsOption.value();
}

void NotifyAddedToGroup(not_null<HistoryItem*> item) {
	constexpr auto kRecent = TimeId(600);
	const auto by = item->from()->asUser();
	if (!ScamDetectorOption.value()
		|| !by
		|| by->isSelf()
		|| by->isContact()
		|| (base::unixtime::now() - item->date() > kRecent)) {
		return;
	}
	const auto chat = item->history()->peer->name();
	const auto who = by->name();
	crl::on_main([=] {
		if (const auto window = Core::App().activeWindow()) {
			auto config = Ui::Toast::Config();
			config.text = TextWithEntities{ u"\u26A0\uFE0F "_q }.append(
				Ui::Text::Bold(u"Вас добавил в группу незнакомец"_q)
			).append(u"\n«%1» добавил вас в «%2». Так рассылают спам, "
				"фишинг и «инвестиции». Можно выйти и пожаловаться."_q.arg(
					who,
					chat));
			config.duration = 10 * crl::time(1000);
			window->uiShow()->showToast(std::move(config));
		}
	});
}

bool GhostStories() {
	return GhostStoriesOption.value();
}

bool GhostMedia() {
	return GhostMediaOption.value();
}

QString MaskPhone(const QString &formatted) {
	if (!HidePhoneOption.value()) {
		return formatted;
	}
	auto result = formatted;
	auto digits = 0;
	for (auto i = result.size(); i > 0; --i) {
		if (result[i - 1].isDigit() && ++digits > 2) {
			result[i - 1] = QChar(0x2022);
		}
	}
	// Keep the country code readable: "+998 •• ••• •• 12".
	for (auto i = 1; i < result.size() && result[i] != ' '; ++i) {
		if (result[i] == QChar(0x2022)) {
			result[i] = formatted[i];
		}
	}
	return result;
}

void Panic() {
	QGuiApplication::clipboard()->clear();
	if (Core::App().domain().local().hasLocalPasscode()) {
		Core::App().lockByPasscode();
	} else if (const auto window = Core::App().activeWindow()) {
		window->widget()->showMinimized();
	}
}

void InstallGlobalGuards() {
	static auto installed = false;
	if (installed) {
		return;
	}
	installed = true;

	class Filter final : public QObject {
	public:
		using QObject::QObject;

	protected:
		bool eventFilter(QObject *object, QEvent *event) override {
			if (event->type() == QEvent::KeyPress && PanicOption.value()) {
				const auto key = static_cast<QKeyEvent*>(event);
				const auto mods = key->modifiers()
					& (Qt::ControlModifier | Qt::AltModifier);
				if (key->key() == Qt::Key_P
					&& mods == (Qt::ControlModifier | Qt::AltModifier)) {
					Panic();
					return true;
				}
			}
			return QObject::eventFilter(object, event);
		}
	};
	qApp->installEventFilter(new Filter(qApp));

	const auto clipboard = QGuiApplication::clipboard();
	const auto timer = new QTimer(qApp);
	timer->setSingleShot(true);
	const auto watched = std::make_shared<QString>();
	QObject::connect(timer, &QTimer::timeout, [=] {
		if (clipboard->text() == *watched) {
			clipboard->clear();
		}
	});
	QObject::connect(clipboard, &QClipboard::dataChanged, [=] {
		if (!ClipboardGuardOption.value()) {
			return;
		}
		const auto text = clipboard->text();
		if (text.isEmpty() || text.size() > 4000) {
			return;
		}
		for (const auto &[index, account] : Core::App().domain().accounts()) {
			if (account->sessionExists()
				&& ContainsLoginCode(&account->session(), text)) {
				*watched = text;
				timer->start(30 * 1000);
				return;
			}
		}
	});
}

bool ShowSeconds() {
	return ShowSecondsOption.value();
}

bool ConfirmRevoke() {
	return ConfirmRevokeOption.value();
}

bool BlockAutoDownload(const QString &name, const QString &mime) {
	if (!NoRiskyAutoDownloadOption.value()) {
		return false;
	}
	const auto report = AnalyzeFileName(name, mime);
	return report.executable || report.atLeast(Severity::High);
}

bool ScamDetectorEnabled() {
	return ScamDetectorOption.value();
}

bool IsStranger(not_null<HistoryItem*> item) {
	const auto user = item->history()->peer->asUser();
	return user
		&& !user->isSelf()
		&& !user->isContact()
		&& !user->isVerified()
		&& !user->isBot()
		&& !item->out();
}

bool StripMetadataEnabled() {
	return StripMetadataOption.value();
}

bool GhostRead() {
	return GhostReadOption.value();
}

bool GhostTyping() {
	return GhostTypingOption.value();
}

bool GhostOnline() {
	return GhostOnlineOption.value();
}

bool ParseIpLike(const QString &host) {
	static const auto re = QRegularExpression("^[0-9.:\\[\\]]+$");
	return re.match(host).hasMatch();
}

void ResolveRedirects(
		const QString &url,
		Fn<void(QStringList, QString)> done) {
	constexpr auto kMaxHops = 10;
	static auto manager = (QNetworkAccessManager*)nullptr;
	if (!manager) {
		manager = new QNetworkAccessManager(qApp);
	}
	const auto hops = std::make_shared<QStringList>(QStringList{ url });
	const auto step = std::make_shared<Fn<void(QUrl)>>();
	*step = [=](QUrl current) {
		auto request = QNetworkRequest(current);
		request.setAttribute(
			QNetworkRequest::RedirectPolicyAttribute,
			QNetworkRequest::ManualRedirectPolicy);
		request.setTransferTimeout(10000);
		request.setHeader(
			QNetworkRequest::UserAgentHeader,
			u"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
				"(KHTML, like Gecko) Chrome/130.0 Safari/537.36"_q);
		const auto reply = manager->head(request);
		QObject::connect(reply, &QNetworkReply::finished, [=] {
			reply->deleteLater();
			const auto location = reply->attribute(
				QNetworkRequest::RedirectionTargetAttribute).toUrl();
			if (!location.isEmpty() && hops->size() <= kMaxHops) {
				const auto next = current.resolved(location);
				hops->push_back(QString::fromUtf8(next.toEncoded()));
				(*step)(next);
				return;
			}
			const auto error = (reply->error() != QNetworkReply::NoError
				&& reply->error() < QNetworkReply::ContentAccessDenied)
				? reply->errorString()
				: (hops->size() > kMaxHops)
				? u"слишком много перенаправлений"_q
				: QString();
			done(*hops, error);
			*step = nullptr; // Break the self reference.
		});
	};
	(*step)(QUrl(url));
}

bool LinkGuardEnabled() {
	return LinkGuard.value();
}

bool FileGuardEnabled() {
	return FileGuard.value();
}

bool InterceptUrlOpen(QString &url, const QVariant &context) {
	const auto scheme = QUrl(url).scheme().toLower();
	if (scheme != u"http"_q && scheme != u"https"_q && scheme != u"ftp"_q) {
		return false;
	}
	if (StripTrackingOption.value()) {
		url = StripTracking(url);
	}
	auto my = context.value<ClickHandlerContext>();
	if (my.secgramChecked || !LinkGuard.value()) {
		return false;
	}
	auto report = AnalyzeUrl(url);
	ApplyFeeds(report, url);
	switch (DomainListed(report.asciiHost)) {
	case DomainList::Allowed: return false;
	case DomainList::Blocked:
		report.add(
			Severity::Critical,
			u"Домен %1 в вашем чёрном списке."_q.arg(report.asciiHost));
		break;
	case DomainList::None: break;
	}
	if (ScamDetectorOption.value() && my.itemId) {
		const auto window = my.sessionWindow.get();
		const auto item = window
			? window->session().data().message(my.itemId)
			: nullptr;
		if (item && IsStranger(item)) {
			report.add(
				Severity::Warning,
				u"Ссылка от незнакомца (его нет в ваших контактах). "
					"Мошенники начинают переписку именно так."_q);
		}
	}
	if (!ConfirmAllLinks.value() && !report.atLeast(Severity::Warning)) {
		return false;
	}
	const auto show = ShowFromContext(context);
	if (!show) {
		return false;
	}
	my.secgramChecked = true;
	const auto checked = QVariant::fromValue(my);
	auto extra = std::vector<Finding>();
	auto baseReport = AnalyzeUrl(url);
	ApplyFeeds(baseReport, url);
	const auto base = baseReport.findings.size();
	for (auto i = base; i < report.findings.size(); ++i) {
		extra.push_back(report.findings[i]);
	}
	show->showBox(Box(LinkCheckBox, LinkCheckArgs{
		.url = url,
		.open = [=](QString chosen) {
			UrlClickHandler::Open(chosen, checked);
		},
		.extra = std::move(extra),
	}));
	return true;
}

void AddLinkFindings(
		not_null<Ui::GenericBox*> box,
		const UrlReport &report,
		const style::FlatLabel &st) {
	if (!LinkGuard.value() || !report.atLeast(Severity::Notice)) {
		return;
	}
	box->addSkip(st::boxLittleSkip);
	AddLabel(box, Ui::Text::Bold(u"SecGram: "_q + Verdict(report)), st);
	if (!report.registrableDomain.isEmpty()) {
		AddLabel(
			box,
			TextWithEntities{ u"Настоящий сайт: "_q }.append(
				Ui::Text::Bold(report.registrableDomain)),
			st);
	}
	AddFindings(box, report, st);
}

void LinkCheckBox(not_null<Ui::GenericBox*> box, LinkCheckArgs args) {
	auto report = AnalyzeUrl(args.url);
	ApplyFeeds(report, args.url);
	for (auto &finding : args.extra) {
		report.findings.push_back(std::move(finding));
	}
	box->setTitle(rpl::single(u"Проверка ссылки"_q));
	box->setWidth(st::boxWideWidth);

	AddLabel(box, Ui::Text::Bold(Verdict(report)));
	box->addSkip(st::boxLittleSkip);
	AddLabel(box, TextWithEntities{ args.url }, st::boxDividerLabel);
	if (!report.asciiHost.isEmpty()) {
		box->addSkip(st::boxLittleSkip);
		auto host = TextWithEntities{ u"Хост: "_q }.append(
			Ui::Text::Bold(report.asciiHost));
		if (report.host != report.asciiHost) {
			host.append(u"(отображается как "_q + report.host + ')');
		}
		AddLabel(box, std::move(host));
		if (!report.registrableDomain.isEmpty()) {
			AddLabel(
				box,
				TextWithEntities{ u"Зарегистрированный домен: "_q }.append(
					Ui::Text::Bold(report.registrableDomain)));
		}
	}
	AddFindings(box, report, st::boxLabel);

	const auto url = args.url;
	const auto clean = report.cleanUrl;
	const auto open = args.open;
	const auto dangerous = report.atLeast(Severity::High);
	if (open) {
		box->addButton(
			rpl::single(dangerous ? u"Всё равно открыть"_q : u"Открыть"_q),
			[=] { box->closeBox(); open(url); },
			dangerous ? st::attentionBoxButton : st::defaultBoxButton);
		if (!report.trackingParams.isEmpty() && clean != url) {
			box->addButton(rpl::single(u"Открыть без трекеров"_q), [=] {
				box->closeBox();
				open(clean);
			});
		}
	}
	box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });
	box->addLeftButton(rpl::single(u"Копировать обезвреженным"_q), [=] {
		CopyWithToast(Defang(url), u"Обезвреженная ссылка скопирована"_q, box->uiShow());
	});

	if (!report.asciiHost.isEmpty()
		&& (report.scheme == u"http"_q || report.scheme == u"https"_q)
		&& !ParseIpLike(report.asciiHost)) {
		box->addSkip(st::boxLittleSkip);
		const auto server = AddLabel(
			box,
			Ui::Text::Link(
				u"Проверить домен (RDAP) и сертификат (запрос с вашего IP)"_q,
				u"internal:secgram_server"_q),
			st::boxDividerLabel);
		const auto host = report.asciiHost;
		server->setClickHandlerFilter([=](const auto &...) {
			server->setText(u"Проверка…"_q);
			CheckServer(host, crl::guard(box, [=](ServerCheck check) {
				auto text = Ui::Text::Bold(Verdict(check.report));
				text.append('\n').append(check.details.join('\n'));
				for (const auto &finding : check.report.findings) {
					text.append('\n')
						.append(SeverityMark(finding.severity) + ' ')
						.append(finding.text);
				}
				server->setMarkedText(text);
			}));
			return false;
		});
	}

	// Following redirects contacts the servers from this computer, so it
	// only happens on an explicit request.
	if (report.scheme == u"http"_q || report.scheme == u"https"_q) {
		box->addSkip(st::boxLittleSkip);
		const auto chain = AddLabel(
			box,
			Ui::Text::Link(
				u"Раскрыть перенаправления (запрос с вашего IP)"_q,
				u"internal:secgram_expand"_q),
			st::boxDividerLabel);
		chain->setClickHandlerFilter([=](const auto &...) {
			chain->setText(u"Запрос…"_q);
			ResolveRedirects(url, crl::guard(box, [=](
					QStringList hops,
					QString error) {
				auto text = TextWithEntities{ u"Цепочка перенаправлений:\n"_q };
				for (auto i = 0; i != hops.size(); ++i) {
					const auto hop = AnalyzeUrl(hops[i]);
					text.append(u"%1. "_q.arg(i + 1));
					text.append(SeverityMark(hop.maxSeverity()) + ' ');
					text.append(Defang(hops[i]));
					text.append('\n');
				}
				if (!error.isEmpty()) {
					text.append(Ui::Text::Bold(u"Ошибка: "_q)).append(error);
				}
				chain->setMarkedText(text);
			}));
			return false;
		});
	}
}

void IocBox(not_null<Ui::GenericBox*> box, QString text) {
	const auto iocs = ExtractIocs(text);
	box->setTitle(rpl::single(u"Индикаторы компрометации"_q));
	box->setWidth(st::boxWideWidth);
	if (iocs.empty()) {
		AddLabel(box, { u"В этом тексте индикаторы не найдены."_q });
		box->addButton(tr::lng_close(), [=] { box->closeBox(); });
		return;
	}
	auto counts = std::map<QString, int>();
	for (const auto &ioc : iocs) {
		++counts[IocTypeName(ioc.type)];
	}
	auto summary = QStringList();
	for (const auto &[type, count] : counts) {
		summary.push_back(u"%1: %2"_q.arg(type).arg(count));
	}
	AddLabel(box, Ui::Text::Bold(
		u"Индикаторов: %1  —  "_q.arg(iocs.size()) + summary.join(u", "_q)));
	box->addSkip(st::boxLittleSkip);
	AddLabel(
		box,
		{ FormatIocs(iocs, IocFormat::Text, true).trimmed() },
		st::boxDividerLabel);

	// Quick lookups in public threat intelligence services.
	constexpr auto kMaxLookups = 30;
	auto lookups = TextWithEntities();
	auto shown = 0;
	for (const auto &ioc : iocs) {
		const auto links = LookupLinks(ioc);
		if (links.empty() || shown++ >= kMaxLookups) {
			continue;
		}
		if (!lookups.empty()) {
			lookups.append('\n');
		}
		lookups.append(Ui::Text::Bold(Defang(ioc.value).left(60)));
		lookups.append(u"\n"_q);
		auto first = true;
		for (const auto &link : links) {
			if (!first) {
				lookups.append(u" \u00B7 "_q);
			}
			first = false;
			lookups.append(Ui::Text::Link(link.service, link.url));
		}
	}
	if (!lookups.empty()) {
		box->addSkip(st::boxLittleSkip);
		AddLabel(box, Ui::Text::Bold(u"Проверить в сервисах "
			"(отправляет только индикатор):"_q));
		AddLabel(box, std::move(lookups));
	}

	const auto show = box->uiShow();
	box->addButton(rpl::single(u"Копировать обезвреженным"_q), [=] {
		CopyWithToast(
			FormatIocs(iocs, IocFormat::Text, true),
			u"Обезвреженные индикаторы скопированы"_q,
			show);
	});
	box->addButton(rpl::single(u"Копировать как есть"_q), [=] {
		CopyWithToast(
			FormatIocs(iocs, IocFormat::Text, false),
			u"Индикаторы скопированы"_q,
			show);
	});
	box->addLeftButton(rpl::single(u"Экспорт"_q), [=] {
		const auto initial = QStandardPaths::writableLocation(
			QStandardPaths::DownloadLocation) + u"/iocs.json"_q;
		FileDialog::GetWritePath(
			box.get(),
			u"Экспорт индикаторов"_q,
			u"JSON (*.json);;CSV (*.csv);;Текст (*.txt);;"
				"STIX 2.1 (*.stix.json);;MISP (*.misp.json);;"
				"TheHive (*.thehive.json)"_q,
			initial,
			[=](QString &&path) {
				const auto lower = path.toLower();
				const auto format = lower.endsWith(u".thehive.json"_q)
					? IocFormat::TheHive
					: lower.endsWith(u".stix.json"_q)
					? IocFormat::Stix
					: lower.endsWith(u".misp.json"_q)
					? IocFormat::Misp
					: lower.endsWith(u".csv"_q)
					? IocFormat::Csv
					: lower.endsWith(u".txt"_q)
					? IocFormat::Text
					: IocFormat::Json;
				auto file = QFile(path);
				if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
					file.write(FormatIocs(iocs, format, false).toUtf8());
					show->showToast(u"Сохранено: "_q + path);
				} else {
					show->showToast(u"Не удалось записать "_q + path);
				}
			});
	});
}

void MessageInfoBox(
		not_null<Ui::GenericBox*> box,
		not_null<HistoryItem*> item) {
	box->setTitle(rpl::single(u"Информация о сообщении"_q));
	box->setWidth(st::boxWideWidth);

	auto json = QJsonObject();
	auto lines = std::vector<std::pair<QString, QString>>();
	const auto add = [&](const QString &key, const QString &value) {
		if (!value.isEmpty()) {
			lines.emplace_back(key, value);
		}
	};
	const auto peer = item->history()->peer;
	add(u"Чат"_q, PeerLine(peer));
	json.insert(u"chat"_q, PeerJson(peer));
	add(u"ID сообщения"_q, QString::number(item->id.bare));
	json.insert(u"message_id"_q, QString::number(item->id.bare));
	if (const auto from = item->from(); from != peer) {
		add(u"Отправитель"_q, PeerLine(from));
		json.insert(u"sender"_q, PeerJson(from));
	}
	add(u"Дата"_q, FormatDate(item->date()));
	json.insert(u"date"_q, qint64(item->date()));
	if (const auto edited = item->Get<HistoryMessageEdited>()) {
		add(u"Изменено"_q, FormatDate(edited->date));
		json.insert(u"edit_date"_q, qint64(edited->date));
	}
	if (const auto forwarded = item->Get<HistoryMessageForwarded>()) {
		auto origin = QJsonObject();
		if (const auto sender = forwarded->originalSender) {
			add(u"Переслано от"_q, PeerLine(sender));
			origin.insert(u"sender"_q, PeerJson(sender));
		} else if (const auto hidden
				= forwarded->originalHiddenSenderInfo.get()) {
			add(
				u"Переслано от"_q,
				hidden->name + u"(скрытый аккаунт, ID недоступен)"_q);
			origin.insert(u"hidden_name"_q, hidden->name);
		}
		if (forwarded->originalId) {
			add(
				u"ID исходного сообщения"_q,
				QString::number(forwarded->originalId.bare));
			origin.insert(
				u"message_id"_q,
				QString::number(forwarded->originalId.bare));
		}
		if (!forwarded->originalPostAuthor.isEmpty()) {
			add(u"Автор оригинала"_q, forwarded->originalPostAuthor);
			origin.insert(u"author"_q, forwarded->originalPostAuthor);
		}
		add(u"Дата оригинала"_q, FormatDate(forwarded->originalDate));
		origin.insert(u"date"_q, qint64(forwarded->originalDate));
		if (forwarded->imported) {
			add(u"Импортировано"_q, u"да (из другого мессенджера)"_q);
		}
		json.insert(u"forward"_q, origin);
	}
	const auto via = item->Get<HistoryMessageVia>();
	auto previewMismatch = QString();
	if (via) {
		if (const auto bot = via->bot) {
			add(u"Через бота"_q, PeerLine(bot));
			json.insert(u"via_bot"_q, PeerJson(bot));
		}
	}
	if (const auto media = item->media()) {
		if (const auto document = media->document()) {
			add(u"Файл"_q, document->filename());
			add(u"MIME"_q, document->mimeString());
			add(u"Размер"_q, FormatSize(document->size));
			add(u"ID документа"_q, QString::number(document->id));
			json.insert(u"file"_q, QJsonObject{
				{ u"name"_q, document->filename() },
				{ u"mime"_q, document->mimeString() },
				{ u"size"_q, qint64(document->size) },
				{ u"id"_q, QString::number(document->id) },
			});
		}
	}
	if (const auto media = item->media()) {
		if (const auto page = media->webpage()) {
			const auto host = QUrl(page->url).host().toLower();
			add(u"Превью ссылки"_q, page->siteName.isEmpty()
				? host
				: (page->siteName + u" \u2014 "_q + host));
			const auto claimed = page->siteName.toLower().remove(' ');
			const auto registered = RegistrableDomain(host).remove('-');
			if (claimed.size() >= 4
				&& !registered.contains(claimed.left(
					std::min(int(claimed.size()), 6)))) {
				previewMismatch = u"Название сайта в превью «%1» не "
					"совпадает с его настоящим доменом %2."_q.arg(
						page->siteName,
						host);
			}
		}
	}
	if (const auto channel = peer->asChannel(); channel && channel->date) {
		add(
			u"Дата канала/группы"_q,
			FormatDate(channel->date)
				+ u" (создание или ваше вступление)"_q);
	}
	for (const auto &bot : { item->from()->asUser(), via ? via->bot : nullptr }) {
		if (!bot || !bot->isBot() || !bot->botInfo) {
			continue;
		}
		const auto info = bot->botInfo.get();
		if (!info->botMenuButtonUrl.isEmpty()) {
			const auto report = AnalyzeUrl(info->botMenuButtonUrl);
			add(
				u"Mini App бота"_q,
				info->botMenuButtonUrl + u"  "_q + Verdict(report));
		}
		if (!info->privacyPolicyUrl.isEmpty()) {
			add(u"Политика бота"_q, info->privacyPolicyUrl);
		}
		if (!info->inlinePlaceholder.isEmpty()) {
			add(u"Инлайн-режим бота"_q, info->inlinePlaceholder);
		}
	}
	// Inline bot buttons hide where they lead: show it.
	if (const auto markup = item->Get<HistoryMessageReplyMarkup>()) {
		using Type = HistoryMessageMarkupButton::Type;
		auto index = 0;
		auto buttons = QJsonArray();
		for (const auto &row : markup->data.rows) {
			for (const auto &button : row) {
				++index;
				auto target = QString();
				auto kind = QString();
				switch (button.type) {
				case Type::Url:
				case Type::Auth:
					kind = u"ссылка"_q;
					target = QString::fromUtf8(button.data);
					break;
				case Type::WebView:
				case Type::SimpleWebView:
					kind = u"мини-приложение"_q;
					target = QString::fromUtf8(button.data);
					break;
				case Type::Callback:
				case Type::CallbackWithPassword:
					kind = u"callback"_q;
					target = QString::fromUtf8(button.data);
					if (target.isEmpty() || !target.isValidUtf16()) {
						target = u"hex:"_q + QString::fromLatin1(button.data.toHex());
					}
					break;
				case Type::CopyText:
					kind = u"копирует текст"_q;
					target = QString::fromUtf8(button.data);
					break;
				case Type::RequestPhone:
					kind = u"⚠ запрашивает ваш номер телефона"_q;
					break;
				case Type::RequestLocation:
					kind = u"⚠ запрашивает ваше местоположение"_q;
					break;
				default:
					break;
				}
				if (kind.isEmpty()) {
					continue;
				}
				auto value = u"«%1» — %2"_q.arg(button.text, kind);
				if (!target.isEmpty()) {
					value += u": "_q + target.left(300);
					if (target.contains(u"://"_q)) {
						value += u"  "_q + Verdict(AnalyzeUrl(target));
					}
				}
				add(u"Кнопка %1"_q.arg(index), value);
				buttons.push_back(QJsonObject{
					{ u"text"_q, button.text },
					{ u"kind"_q, kind },
					{ u"target"_q, target },
				});
			}
		}
		if (!buttons.isEmpty()) {
			json.insert(u"buttons"_q, buttons);
		}
	}
	if (const auto media = item->media()) {
		const auto document = media->document();
		const auto sticker = document ? document->sticker() : nullptr;
		// Since 2021 a sticker set id keeps its creator id in the high bits.
		if (sticker && (sticker->set.id >> 32)) {
			const auto owner = QString::number(sticker->set.id >> 32);
			add(
				u"Создатель набора стикеров"_q,
				u"вероятно, пользователь ID "_q + owner);
			json.insert(u"sticker_set_owner_id"_q, owner);
		}
	}
	if (item->hasDirectLink()) {
		const auto link = item->history()->session().api()
			.exportDirectMessageLink(item, false);
		add(u"Ссылка"_q, link);
		json.insert(u"link"_q, link);
	}
	const auto text = item->originalText().text;
	if (!text.isEmpty()) {
		const auto iocs = ExtractIocs(text);
		if (!iocs.empty()) {
			add(u"Индикаторы"_q, QString::number(iocs.size()));
		}
		json.insert(u"text"_q, text);
	}

	auto plain = QString();
	for (const auto &[key, value] : lines) {
		AddLabel(
			box,
			Ui::Text::Bold(key + u": "_q).append(value));
		box->addSkip(st::boxLittleSkip);
		plain += key + u": "_q + value + '\n';
	}

	if (!previewMismatch.isEmpty()) {
		box->addSkip(st::boxLittleSkip);
		AddLabel(box, TextWithEntities{ SeverityMark(Severity::High) + ' ' }
			.append(Ui::Text::Bold(u"Превью: "_q))
			.append(previewMismatch));
	}
	if (!text.isEmpty()) {
		const auto scam = AnalyzeMessageText(text, IsStranger(item));
		if (scam.atLeast(Severity::Notice)) {
			box->addSkip(st::boxLittleSkip);
			AddLabel(box, Ui::Text::Bold(u"Текст: "_q + Verdict(scam)));
			AddFindings(box, scam, st::boxLabel);
		}
	}

	// Impersonation red flags of everyone involved.
	auto people = std::vector<not_null<PeerData*>>{ item->from() };
	if (peer != item->from() && !peer->isUser()) {
		people.push_back(peer); // Fake "official" groups and channels.
	}
	if (const auto forwarded = item->Get<HistoryMessageForwarded>()) {
		if (forwarded->originalSender) {
			people.push_back(forwarded->originalSender);
		}
	}
	for (const auto &person : people) {
		const auto history = NameHistory(person);
		if (!history.empty()) {
			auto lines = QStringList();
			for (const auto &change : history) {
				lines.push_back(u"до %1: %2%3"_q.arg(
					base::unixtime::parse(change.at).toString(
						u"yyyy-MM-dd HH:mm"_q),
					change.name,
					change.username.isEmpty()
						? QString()
						: (u" (@"_q + change.username + ')')));
			}
			box->addSkip(st::boxLittleSkip);
			AddLabel(box, Ui::Text::Bold(
				u"История имён «%1»:"_q.arg(person->name())));
			AddLabel(box, { lines.join('\n') }, st::boxDividerLabel);
			plain += u"История имён: "_q + lines.join(u"; "_q) + '\n';
		}
		if (const auto note = PeerNote(person); !note.isEmpty()) {
			box->addSkip(st::boxLittleSkip);
			AddLabel(box, Ui::Text::Bold(
				u"\U0001F4DD Ваша заметка о «%1»: "_q.arg(person->name())
			).append(note));
		}
		const auto risk = PeerRisk(person);
		if (!risk.atLeast(Severity::Notice)) {
			continue;
		}
		box->addSkip(st::boxLittleSkip);
		AddLabel(box, Ui::Text::Bold(person->name() + u": "_q + Verdict(risk)));
		AddFindings(box, risk, st::boxLabel);
		for (const auto &finding : risk.findings) {
			plain += SeverityName(finding.severity)
				+ u": "_q
				+ finding.text
				+ '\n';
		}
	}

	const auto show = box->uiShow();
	const auto jsonText = QString::fromUtf8(
		QJsonDocument(json).toJson(QJsonDocument::Indented));
	box->addButton(rpl::single(u"Копировать"_q), [=] {
		CopyWithToast(plain, u"Информация скопирована"_q, show);
	});
	box->addButton(rpl::single(u"Копировать JSON"_q), [=] {
		CopyWithToast(jsonText, u"JSON скопирован"_q, show);
	});
	box->addLeftButton(tr::lng_close(), [=] { box->closeBox(); });
}

void FileCheckBox(
		not_null<Ui::GenericBox*> box,
		not_null<DocumentData*> document) {
	const auto name = document->filename();
	const auto mime = document->mimeString();
	auto report = AnalyzeFileName(name, mime);
	box->setTitle(rpl::single(u"Проверка файла"_q));
	box->setWidth(st::boxWideWidth);

	const auto verdict = AddLabel(box, Ui::Text::Bold(Verdict(report)));
	box->addSkip(st::boxLittleSkip);
	AddLabel(
		box,
		Ui::Text::Bold(u"Имя: "_q).append(report.displayName));
	AddLabel(box, Ui::Text::Bold(u"Заявленный тип: "_q).append(mime));
	AddLabel(box, Ui::Text::Bold(u"Размер: "_q).append(
		FormatSize(document->size)));
	AddFindings(box, report, st::boxLabel);
	box->addSkip(st::boxLittleSkip);

	const auto path = document->filepath(true);
	const auto hashes = AddLabel(
		box,
		{ path.isEmpty()
			? u"Скачайте файл, чтобы вычислить хеши и проверить настоящий "
				"тип содержимого."_q
			: u"Вычисление хешей…"_q },
		st::boxDividerLabel);
	const auto sha256 = box->lifetime().make_state<QString>();
	const auto show = box->uiShow();

	if (!path.isEmpty()) {
		crl::async([=] {
			auto result = ComputeFileHashes(path);
			auto container = ContainerReport();
			constexpr auto kContainerLimit = qint64(256 * 1024 * 1024);
			if (result.ok && result.size <= kContainerLimit) {
				auto file = QFile(path);
				if (file.open(QIODevice::ReadOnly)) {
					container = AnalyzeContainer(file.readAll());
				}
			}
			crl::on_main(box.get(), [=] {
				if (!result.ok) {
					hashes->setText(u"Не удалось прочитать файл."_q);
					return;
				}
				*sha256 = result.sha256;
				auto copy = report;
				ApplyContentCheck(copy, result);
				for (const auto &finding : container.findings) {
					copy.findings.push_back(finding);
				}
				verdict->setMarkedText(Ui::Text::Bold(Verdict(copy)));
				auto text = u"SHA-256: %1\nSHA-1: %2\nMD5: %3"_q.arg(
					result.sha256,
					result.sha1,
					result.md5);
				if (!result.magicType.isEmpty()) {
					text += u"\nНастоящее содержимое: "_q + result.magicType;
				}
				for (auto i = report.findings.size();
						i < copy.findings.size();
						++i) {
					const auto &finding = copy.findings[i];
					text += u"\n"_q
						+ SeverityMark(finding.severity)
						+ ' '
						+ finding.text;
				}
				if (!container.summary.isEmpty()) {
					text += u"\n\n"_q + container.summary;
				}
				hashes->setText(text);
			});
		});
		box->addButton(rpl::single(u"VirusTotal"_q), [=] {
			if (!sha256->isEmpty()) {
				// Only the hash is looked up, the file is never uploaded.
				File::OpenUrl(VirusTotalHashUrl(*sha256));
			}
		});
		box->addButton(rpl::single(u"Копировать SHA-256"_q), [=] {
			if (!sha256->isEmpty()) {
				CopyWithToast(*sha256, u"SHA-256 скопирован"_q, show);
			}
		});
		box->addLeftButton(rpl::single(u"Показать в папке"_q), [=] {
			File::ShowInFolder(path);
		});
		const auto addScanner = [&](
				const QString &title,
				auto scan) {
			box->addSkip(st::boxLittleSkip);
			const auto label = AddLabel(
				box,
				Ui::Text::Link(title, u"internal:secgram_scan"_q),
				st::boxDividerLabel);
			label->setClickHandlerFilter([=](const auto &...) {
				label->setText(u"Сканирование…"_q);
				scan(path, crl::guard(box, [=](QString result) {
					label->setText(result);
				}));
				return false;
			});
		};
		if (ClamAvAvailable()) {
			addScanner(u"Сканировать антивирусом ClamAV"_q, ScanWithClamAv);
		}
		if (YaraAvailable()) {
			addScanner(u"Проверить правилами YARA"_q, ScanWithYara);
		}
	} else {
		box->addButton(tr::lng_close(), [=] { box->closeBox(); });
	}
}

bool InterceptFileLaunch(const QString &path, Fn<void()> launch) {
	if (!FileGuard.value()) {
		return false;
	}
	auto report = AnalyzeFileName(QFileInfo(path).fileName());
	auto head = QByteArray();
	if (auto file = QFile(path); file.open(QIODevice::ReadOnly)) {
		head = file.read(0x10000);
	}
	auto content = FileHashes();
	content.magicType = DetectMagicType(head, &content.magicExecutable);
	content.ok = true;
	ApplyContentCheck(report, content);
	constexpr auto kLaunchContainerLimit = qint64(64 * 1024 * 1024);
	auto container = ContainerReport();
	if (QFileInfo(path).size() <= kLaunchContainerLimit
		&& (head.startsWith("PK\x03\x04")
			|| head.startsWith("%PDF")
			|| head.startsWith("MZ")
			|| head.startsWith("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"))) {
		if (auto file = QFile(path); file.open(QIODevice::ReadOnly)) {
			container = AnalyzeContainer(file.readAll());
		}
		for (const auto &finding : container.findings) {
			report.findings.push_back(finding);
		}
	}
	const auto blocked = BlockExecutablesOption.value()
		&& (report.executable || content.magicExecutable);
	if (!report.atLeast(Severity::High) && !blocked) {
		return false;
	}
	const auto window = Core::App().activeWindow();
	if (!window) {
		return false;
	}
	window->uiShow()->showBox(Box([=](not_null<Ui::GenericBox*> box) {
		box->setTitle(rpl::single(u"Опасный файл"_q));
		box->setWidth(st::boxWideWidth);
		AddLabel(box, Ui::Text::Bold(Verdict(report)));
		box->addSkip(st::boxLittleSkip);
		AddLabel(box, Ui::Text::Bold(u"Файл: "_q).append(report.displayName));
		if (!content.magicType.isEmpty()) {
			AddLabel(
				box,
				Ui::Text::Bold(u"Настоящее содержимое: "_q).append(content.magicType));
		}
		AddFindings(box, report, st::boxLabel);
		if (!container.summary.isEmpty()) {
			box->addSkip(st::boxLittleSkip);
			AddLabel(box, { container.summary }, st::boxDividerLabel);
		}
		box->addSkip(st::boxLittleSkip);
		AddLabel(
			box,
			{ u"Открывайте, только если доверяете отправителю и ждали "
				"именно этот файл. Проверьте хеш на VirusTotal или откройте "
				"в песочнице / виртуальной машине."_q },
			st::boxDividerLabel);
		if (blocked) {
			AddLabel(box, Ui::Text::Bold(u"Запуск программ из чатов "
				"запрещён в настройках SecGram."_q));
		} else {
			box->addButton(rpl::single(u"Всё равно открыть"_q), [=] {
				box->closeBox();
				launch();
			}, st::attentionBoxButton);
		}
		box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });
		box->addLeftButton(rpl::single(u"Показать в папке"_q), [=] {
			box->closeBox();
			File::ShowInFolder(path);
		});
		if (SandboxAvailable() && !blocked) {
			box->addButton(rpl::single(u"Открыть в песочнице"_q), [=] {
				box->closeBox();
				OpenInSandbox(path);
			});
		}
	}));
	return true;
}

void SettingsBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller) {
	box->setTitle(rpl::single(u"Безопасность SecGram"_q));
	box->setWidth(st::boxWideWidth);
	const auto container = box->verticalLayout();

	Settings::AddButtonWithLabel(
		container,
		rpl::single(u"Проверить обновления"_q),
		rpl::single(QString::fromLatin1(kVersion)),
		st::settingsButton,
		{ &st::menuIconRestore }
	)->setClickedCallback([=] {
		controller->showToast(u"Проверка обновлений…"_q);
		CheckForUpdatesNow(controller);
	});
	Settings::AddButtonWithIcon(
		container,
		rpl::single(u"Аудит безопасности аккаунта"_q),
		st::settingsButton,
		{ &st::menuIconAntispam }
	)->setClickedCallback([=] {
		controller->show(Box(SecurityAuditBox, controller));
	});
	Ui::AddDividerText(
		container,
		rpl::single(u"Проверка 2FA, сеансов, приватности номера и "
			"локального пароля с рекомендациями."_q));
	Settings::AddButtonWithIcon(
		container,
		rpl::single(u"Список наблюдения"_q),
		st::settingsButton,
		{ &st::menuIconSearch }
	)->setClickedCallback([=] {
		controller->show(Box(WatchlistBox, controller));
	});
	Ui::AddDividerText(
		container,
		rpl::single(u"Слова, домены, IP и кошельки, о появлении которых в "
			"любом чате нужно сразу узнать."_q));
	{
		const auto feeds = Settings::AddButtonWithLabel(
			container,
			rpl::single(u"Обновить базы фишинга"_q),
			rpl::single(ThreatFeedsInfo()),
			st::settingsButton,
			{ &st::menuIconRestore });
		feeds->setClickedCallback([=] {
			controller->showToast(u"Загрузка OpenPhish и Phishing Army…"_q);
			UpdateThreatFeeds(crl::guard(box, [=](int count, QString error) {
				controller->showToast(count
					? (u"Базы обновлены: %1 адресов. "_q.arg(count) + error)
					: (u"Не удалось обновить: "_q + error));
			}));
		});
		Ui::AddDividerText(
			container,
			rpl::single(u"Тысячи активных фишинговых и вредоносных адресов из "
				"OpenPhish и Phishing Army. Ссылки сверяются с базой локально."_q));
	}
	Settings::AddButtonWithIcon(
		container,
		rpl::single(u"Шаблоны ответов"_q),
		st::settingsButton,
		{ &st::menuIconCopy }
	)->setClickedCallback([=] {
		controller->show(Box(TemplatesBox));
	});
	Settings::AddButtonWithIcon(
		container,
		rpl::single(u"Экспорт настроек для команды"_q),
		st::settingsButton,
		{ &st::menuIconDownload }
	)->setClickedCallback([=] {
		ExportTeamConfig(controller->uiShow());
	});
	Settings::AddButtonWithIcon(
		container,
		rpl::single(u"Импорт настроек команды"_q),
		st::settingsButton,
		{ &st::menuIconRestore }
	)->setClickedCallback([=] {
		ImportTeamConfig(controller->uiShow());
	});
	Settings::AddButtonWithIcon(
		container,
		rpl::single(u"Открыть собранные IOC (CSV)"_q),
		st::settingsButton,
		{ &st::menuIconShowInFolder }
	)->setClickedCallback([=] {
		const auto path = IocFeedPath(&controller->session());
		if (QFile::exists(path)) {
			File::ShowInFolder(path);
		} else {
			controller->showToast(u"Пока пусто. Включите сбор IOC в меню "
				"нужного чата или канала."_q);
		}
	});
	Settings::AddButtonWithIcon(
		container,
		rpl::single(u"Папка правил YARA"_q),
		st::settingsButton,
		{ &st::menuIconFile }
	)->setClickedCallback([=] {
		QDir().mkpath(YaraRulesFolder());
		File::ShowInFolder(YaraRulesFolder());
	});
	Ui::AddDividerText(
		container,
		rpl::single(u"Шаблоны для быстрых ответов, общий набор списков "
			"для команды SOC, IOC, собранные из каналов, и ваши правила "
			"YARA (*.yar). ClamAV, YARA и firejail используются, если "
			"установлены в системе."_q));
	Settings::AddButtonWithIcon(
		container,
		rpl::single(u"Свои списки доменов"_q),
		st::settingsButton,
		{ &st::menuIconBlock }
	)->setClickedCallback([=] {
		controller->show(Box(DomainListsBox));
	});
	Ui::AddDividerText(
		container,
		rpl::single(u"Доверенные и запрещённые домены для проверки "
			"ссылок."_q));
	Ui::AddSkip(container);

	struct Row {
		const char *id;
		const char *title;
		const char *about;
	};
	struct Group {
		const char *title;
		std::vector<Row> rows;
	};
	const auto groups = std::vector<Group>{
		{ "Защита аккаунта", {
			{ kOptionNewLoginAlert, "Предупреждение о новом входе",
				"Окно при входе с нового устройства с кнопкой "
				"немедленного завершения сеанса." },
			{ kOptionLoginCodeGuard, "Защита кода входа",
				"Предупреждать при попытке отправить или переслать код "
				"входа от Telegram — главный способ угона аккаунтов." },
		} },
		{ "Защита", {
			{ kOptionPanic, "Кнопка паники: Ctrl+Alt+P",
				"Мгновенная блокировка код-паролем (или сворачивание) и "
				"очистка буфера обмена." },
			{ kOptionLinkGuard, "Проверка ссылок",
				"Каждая ссылка анализируется перед открытием: поддельные "
				"буквы, имитация брендов, IP-адреса, сокращатели, "
				"перенаправления, скачивание .exe." },
			{ kOptionConfirmAllLinks, "Подтверждать каждую ссылку",
				"Показывать окно анализа даже для безопасных на вид "
				"ссылок." },
			{ kOptionBlockExecutables, "Запретить запуск программ",
				"Исполняемые файлы и скрипты из чатов нельзя открыть — "
				"только показать в папке." },
			{ kOptionNoRiskyAutoDownload, "Не скачивать опасное "
				"автоматически",
				"Автозагрузка пропускает программы, скрипты, макросы и "
				"замаскированные файлы." },
			{ kOptionFileGuard, "Проверка файлов",
				"Проверка скачанного файла перед открытием: RTLO, "
				"двойное расширение, программа под видом документа, "
				"Office с макросами." },
		} },
		{ "Конфиденциальность", {
			{ kOptionStripTracking, "Удалять трекеры из ссылок",
				"Удалять utm_*, fbclid, gclid и другие параметры слежки." },
			{ kOptionStripMetadata, "Удалять метаданные фото",
				"Удалять GPS-координаты, данные камеры и серийные номера "
				"из фото (JPEG/PNG) и видео (MP4/MOV)." },
			{ kOptionGhostRead, "Не отправлять отметку о прочтении",
				"Отправитель не увидит, что вы прочитали сообщение. Если "
				"вы напишете в чат, сообщения всё равно станут "
				"прочитанными." },
			{ kOptionGhostTyping, "Скрывать «печатает…»",
				"Не отправлять статусы набора текста, записи голоса и "
				"загрузки." },
			{ kOptionGhostStories, "Незаметный просмотр историй",
				"Автор истории не узнает, что вы её посмотрели." },
			{ kOptionGhostMedia, "Не отмечать голосовые прослушанными",
				"Собеседник не увидит, что вы прослушали голосовое или "
				"видеосообщение." },
			{ kOptionNoLinkPreviews, "Отправлять ссылки без превью",
				"К вашим ссылкам не прикрепляется превью сайта." },
			{ kOptionHidePhone, "Скрывать свой номер на экране",
				"Номер телефона в интерфейсе маскируется — для "
				"демонстрации экрана." },
			{ kOptionClipboardGuard, "Очищать буфер от кода входа",
				"Скопированный код входа удаляется из буфера через 30 с." },
			{ kOptionGhostOnline, "Всегда оффлайн",
				"Не отправлять статус «в сети». При отправке сообщения "
				"вы можете на мгновение появиться в сети." },
		} },
		{ "Удобство", {
			{ kOptionShowSeconds, "Время с секундами",
				"Показывать время сообщений с секундами. Нужен "
				"перезапуск." },
			{ kOptionConfirmRevoke, "Подтверждать удаление у всех",
				"Дополнительный вопрос перед удалением сообщений у "
				"собеседника." },
		} },
		{ "Инструменты расследования", {
			{ kOptionScamDetector, "Детектор мошенничества",
				"Предупреждение о сообщениях с признаками мошенничества "
				"и о ссылках от людей не из контактов." },
			{ kOptionWatchlist, "Список наблюдения",
				"Уведомлять о совпадениях со списком наблюдения во "
				"входящих сообщениях." },
			{ kOptionNameHistory, "История имён",
				"Запоминать прежние имена и юзернеймы — видно в "
				"«Информация и ID»." },
			{ kOptionContextTools, "Раздел SecGram в меню сообщения",
				"В меню по правой кнопке: информация и ID, извлечение "
				"IOC, обезвреживание, проверка ссылок и файлов." },
			{ kOptionKeepInChat, "Удалённые и изменённые — прямо в чате",
				"Удалённое собеседником остаётся в чате с пометкой "
				"«Удалено» и временем, у изменённых видны прежние "
				"версии. Видно только вам." },
			{ kOptionHistoryLog, "Сохранять удалённые и изменённые сообщения",
				"Сохраняются сообщения, удалённые другими, и текст до "
				"изменения. Просмотр — из меню чата. Журнал шифруется." },
			{ kOptionEncryptLogs, "Шифровать журналы SecGram",
				"AES-256-GCM ключом, защищённым локальным код-паролем. "
				"Установите код-пароль, чтобы защита была полной." },
			{ "show-peer-id-below-about", "Показывать ID в профиле",
				"Показывать ID пользователей, групп и каналов в профиле." },
		} },
	};
	for (const auto &group : groups) {
		Ui::AddSubsectionTitle(
			container,
			rpl::single(QString::fromUtf8(group.title)));
		for (const auto &row : group.rows) {
			auto &option = base::options::lookup<bool>(row.id);
			const auto button = Settings::AddButtonWithIcon(
				container,
				rpl::single(QString::fromUtf8(row.title)),
				st::settingsButtonNoIcon);
			button->toggleOn(rpl::single(option.value()));
			button->toggledChanges(
			) | rpl::on_next([=, &option](bool toggled) {
				option.set(toggled);
			}, button->lifetime());
			Ui::AddDividerText(
				container,
				rpl::single(QString::fromUtf8(row.about)));
		}
		Ui::AddSkip(container);
	}
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
}

void DecodeBox(not_null<Ui::GenericBox*> box, QString text) {
	box->setTitle(rpl::single(u"Декодирование"_q));
	box->setWidth(st::boxWideWidth);
	auto any = false;
	auto all = QString();
	// Each whitespace separated token is tried, plus the whole text.
	auto tokens = text.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
	if (tokens.size() > 1) {
		tokens.push_front(text);
	}
	tokens.removeDuplicates();
	for (const auto &token : tokens.mid(0, 50)) {
		const auto decoded = DecodeText(token);
		if (decoded.empty()) {
			continue;
		}
		any = true;
		AddLabel(box, Ui::Text::Bold(token.left(80)
			+ (token.size() > 80 ? u"…"_q : QString())));
		for (const auto &entry : decoded) {
			AddLabel(
				box,
				Ui::Text::Bold(entry.kind + u": "_q).append(entry.value),
				st::boxDividerLabel);
			all += entry.kind + u": "_q + entry.value + '\n';
		}
		box->addSkip(st::boxLittleSkip);
	}
	if (!any) {
		AddLabel(box, { u"Не найдено ничего, что можно декодировать."_q });
	} else {
		box->addButton(rpl::single(u"Копировать"_q), [=] {
			CopyWithToast(all, u"Скопировано"_q, box->uiShow());
		});
	}
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
}

void FillMessageMenu(
		not_null<Ui::PopupMenu*> menu,
		not_null<HistoryView::ListWidget*> list,
		const HistoryView::ContextMenuRequest &request) {
	if (!ContextTools.value()) {
		return;
	}
	const auto controller = list->controller();
	const auto show = controller->uiShow();
	const auto item = request.item;
	const auto itemId = item ? item->fullId() : FullMsgId();
	const auto session = &controller->session();

	auto sub = std::make_unique<Ui::PopupMenu>(
		menu,
		st::popupMenuWithIcons);
	if (item) {
		sub->addAction(u"Информация и ID"_q, [=] {
			if (const auto found = session->data().message(itemId)) {
				show->showBox(Box(MessageInfoBox, not_null(found)));
			}
		}, &st::menuIconInfo);
	}
	const auto text = CollectText(list, request);
	if (!text.trimmed().isEmpty()) {
		sub->addAction(u"Извлечь IOC"_q, [=] {
			show->showBox(Box(IocBox, text));
		}, &st::menuIconSearch);
		const auto defanged = DefangText(text);
		if (defanged != text) {
			sub->addAction(u"Копировать текст обезвреженным"_q, [=] {
				CopyWithToast(defanged, u"Обезвреженный текст скопирован"_q, show);
			}, &st::menuIconCopy);
		}
	}
	{
		const auto selected = request.selectedText.rich.text.trimmed();
		const auto source = !selected.isEmpty()
			? selected
			: item
			? item->originalText().text.trimmed()
			: QString();
		if (!source.isEmpty() && source.size() < 20000) {
			sub->addAction(u"Декодировать (Base64, Hex, JWT…)"_q, [=] {
				show->showBox(Box(DecodeBox, source));
			}, &st::menuIconEdit);
		}
	}
	if (item && HasLoggedEdits(item)) {
		sub->addAction(u"История правок сообщения"_q, [=] {
			if (const auto found = session->data().message(itemId)) {
				show->showBox(Box(
					HistoryLogBox,
					session,
					found->history()->peer.get(),
					found->id));
			}
		}, &st::menuIconEdit);
	}
	if (item) {
		const auto peer = item->from();
		sub->addAction(u"Заметка о «%1»"_q.arg(peer->name()), [=] {
			show->showBox(Box(PeerNoteBox, peer));
		}, &st::menuIconEdit);
	}
	if (const auto link = request.link) {
		const auto url = link->copyToClipboardText();
		if (url.contains(u"://"_q)) {
			sub->addAction(u"Проверить ссылку"_q, [=] {
				show->showBox(Box(LinkCheckBox, LinkCheckArgs{
					.url = url,
					.open = [=](QString chosen) {
						auto context = ClickHandlerContext();
						context.secgramChecked = true;
						context.sessionWindow = base::make_weak(controller.get());
						UrlClickHandler::Open(
							chosen,
							QVariant::fromValue(context));
					},
				}));
			}, &st::menuIconLink);
			sub->addAction(u"Копировать ссылку обезвреженной"_q, [=] {
				CopyWithToast(Defang(url), u"Обезвреженная ссылка скопирована"_q, show);
			}, &st::menuIconCopy);
		}
	}
	if (item) {
		if (const auto media = item->media()) {
			if (const auto document = media->document()) {
				sub->addAction(u"Проверить файл и хеши"_q, [=] {
					show->showBox(Box(FileCheckBox, not_null(document)));
				}, &st::menuIconFile);
			}
		}
	}
	{
		auto ids = std::vector<FullMsgId>();
		if (request.overSelection && !request.selectedItems.empty()) {
			for (const auto &selected : request.selectedItems) {
				ids.push_back(selected.msgId);
			}
		} else if (item) {
			ids.push_back(itemId);
		}
		if (!ids.empty()) {
			sub->addAction(
				(ids.size() > 1)
					? u"Экспорт доказательств (%1)"_q.arg(ids.size())
					: u"Экспорт доказательств"_q,
				[=] {
					auto items = std::vector<not_null<HistoryItem*>>();
					for (const auto &id : ids) {
						if (const auto found = session->data().message(id)) {
							items.push_back(found);
						}
					}
					ExportEvidence(show, std::move(items));
				},
				&st::menuIconDownload);
		}
	}
	if (sub->empty()) {
		return;
	}
	menu->addSeparator();
	menu->addAction(u"SecGram"_q, std::move(sub), &st::menuIconAntispam);
}

} // namespace SecGram
