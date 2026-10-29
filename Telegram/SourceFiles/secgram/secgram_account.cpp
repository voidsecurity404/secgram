/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "secgram/secgram_account.h"

#include "api/api_authorizations.h"
#include "api/api_cloud_password.h"
#include "api/api_user_privacy.h"
#include "apiwrap.h"
#include "base/options.h"
#include "base/unixtime.h"
#include "core/application.h"
#include "core/core_cloud_password.h"
#include "data/data_authorization.h"
#include "data/data_session.h"
#include "history/history.h"
#include "history/history_item.h"
#include "history/view/history_view_element.h"
#include "lang/lang_keys.h"
#include "main/main_domain.h"
#include "main/main_session.h"
#include "secgram/secgram_ui.h"
#include "settings/sections/settings_active_sessions.h"
#include "settings/sections/settings_privacy_security.h"
#include "storage/storage_domain.h"
#include "ui/layers/generic_box.h"
#include "ui/layers/show.h"
#include "ui/text/text_utilities.h"
#include "ui/widgets/labels.h"
#include "window/window_controller.h"
#include "window/window_session_controller.h"

#include "styles/style_layers.h"
#include "styles/style_widgets.h"

#include <QtCore/QRegularExpression>

namespace SecGram {
namespace {

constexpr auto kServiceUserId = 777000;
constexpr auto kCodeLifetime = TimeId(24 * 3600);
constexpr auto kScannedMessages = 30;
constexpr auto kStaleSessionDays = 30;

base::options::toggle NewLoginAlert({
	.id = kOptionNewLoginAlert,
	.name = "Предупреждение о новом входе",
	.description = "Показывать окно, когда в аккаунт входят с нового "
		"устройства, с возможностью сразу завершить этот сеанс.",
	.defaultValue = true,
});

base::options::toggle LoginCodeGuard({
	.id = kOptionLoginCodeGuard,
	.name = "Защита кода входа",
	.description = "Предупреждать, если вы пытаетесь отправить или "
		"переслать кому-то код входа от Telegram.",
	.defaultValue = true,
});

// Set while re-sending after the user explicitly confirmed.
bool Confirmed = false;

[[nodiscard]] std::shared_ptr<Ui::Show> ActiveShow() {
	const auto window = Core::App().activeWindow();
	return window ? window->uiShow() : nullptr;
}

[[nodiscard]] PeerId ServicePeerId() {
	return peerFromUser(UserId(kServiceUserId));
}

[[nodiscard]] bool LooksLikeCodeMessage(const QString &text) {
	static const auto re = QRegularExpression(
		"code|код|kod|login|вход",
		QRegularExpression::CaseInsensitiveOption);
	return re.match(text).hasMatch();
}

[[nodiscard]] QStringList CodesIn(const QString &text) {
	static const auto re = QRegularExpression("(?<!\\d)(\\d{5,6})(?!\\d)");
	auto result = QStringList();
	auto i = re.globalMatch(text);
	while (i.hasNext()) {
		result.push_back(i.next().captured(1));
	}
	return result;
}

[[nodiscard]] QStringList RecentLoginCodes(
		not_null<Main::Session*> session) {
	const auto history = session->data().historyLoaded(ServicePeerId());
	if (!history) {
		return {};
	}
	const auto now = base::unixtime::now();
	auto result = QStringList();
	const auto check = [&](not_null<HistoryItem*> item) {
		if (now - item->date() > kCodeLifetime) {
			return;
		}
		const auto &text = item->originalText().text;
		if (LooksLikeCodeMessage(text)) {
			result.append(CodesIn(text));
		}
	};
	if (const auto last = history->lastMessage()) {
		check(last);
	}
	auto scanned = 0;
	for (auto b = history->blocks.rbegin(); b != history->blocks.rend(); ++b) {
		const auto &messages = (*b)->messages;
		for (auto m = messages.rbegin(); m != messages.rend(); ++m) {
			check((*m)->data());
			if (++scanned >= kScannedMessages) {
				return result;
			}
		}
	}
	return result;
}

void ShowCodeWarning(Fn<void()> proceed, bool forward) {
	const auto show = ActiveShow();
	if (!show) {
		return;
	}
	show->showBox(Box([=](not_null<Ui::GenericBox*> box) {
		box->setTitle(rpl::single(u"Это код входа в Telegram!"_q));
		box->setWidth(st::boxWideWidth);
		box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			rpl::single(Ui::Text::Bold(forward
				? u"Вы пересылаете сообщение с кодом входа в ваш аккаунт."_q
				: u"Ваше сообщение содержит код входа в ваш аккаунт."_q)),
			st::boxLabel));
		box->addSkip(st::boxLittleSkip);
		box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			u"С этим кодом любой человек получит полный доступ к вашему "
				"аккаунту: переписке, контактам, файлам.\n\n"
				"Telegram, поддержка, банки и «служба безопасности» "
				"НИКОГДА не просят этот код. Если его кто-то просит — "
				"это мошенник."_q,
			st::boxLabel));
		box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });
		box->addButton(rpl::single(u"Всё равно отправить"_q), [=] {
			box->closeBox();
			Confirmed = true;
			proceed();
			Confirmed = false;
		}, st::attentionBoxButton);
	}));
}

struct AuditRow {
	not_null<Ui::FlatLabel*> label;
	QString title;
};

[[nodiscard]] TextWithEntities AuditText(
		const QString &mark,
		const QString &title,
		const QString &details) {
	auto result = TextWithEntities{ mark + ' ' };
	result.append(Ui::Text::Bold(title));
	if (!details.isEmpty()) {
		result.append('\n').append(details);
	}
	return result;
}

[[nodiscard]] AuditRow AddAuditRow(
		not_null<Ui::GenericBox*> box,
		const QString &title) {
	const auto label = box->addRow(object_ptr<Ui::FlatLabel>(
		box,
		rpl::single(AuditText(u"⏳"_q, title, u"Проверка…"_q)),
		st::boxLabel));
	label->setSelectable(true);
	box->addSkip(st::boxLittleSkip);
	return { label, title };
}

void SetAudit(
		const AuditRow &row,
		bool ok,
		const QString &details,
		bool warningOnly = false) {
	const auto mark = ok
		? u"✅"_q
		: warningOnly
		? u"⚠️"_q
		: u"❌"_q;
	row.label->setMarkedText(AuditText(mark, row.title, details));
}

} // namespace

const char kOptionNewLoginAlert[] = "secgram-new-login-alert";
const char kOptionLoginCodeGuard[] = "secgram-login-code-guard";

void NotifyNewAuthorization(
		const Data::UnreviewedAuth &auth,
		Fn<void(bool confirm)> review) {
	if (!NewLoginAlert.value()) {
		return;
	}
	const auto show = ActiveShow();
	if (!show) {
		return;
	}
	const auto device = auth.device;
	const auto location = auth.location;
	const auto date = auth.date
		? base::unixtime::parse(auth.date).toString(
			u"yyyy-MM-dd HH:mm:ss"_q)
		: QString();
	show->showBox(Box([=](not_null<Ui::GenericBox*> box) {
		box->setTitle(rpl::single(u"\U0001F6A8 Новый вход в аккаунт"_q));
		box->setWidth(st::boxWideWidth);
		box->setCloseByOutsideClick(false);
		auto text = TextWithEntities{ u"В ваш аккаунт вошли с нового "
			"устройства:\n\n"_q };
		text.append(Ui::Text::Bold(u"Устройство: "_q)).append(device);
		text.append('\n').append(Ui::Text::Bold(u"Местоположение: "_q))
			.append(location);
		if (!date.isEmpty()) {
			text.append('\n').append(Ui::Text::Bold(u"Время: "_q))
				.append(date);
		}
		text.append(u"\n\nЕсли это были не вы — немедленно завершите "
			"сеанс, затем включите облачный пароль (2FA) и проверьте "
			"активные сеансы."_q);
		box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			rpl::single(text),
			st::boxLabel));
		box->addButton(rpl::single(u"Это не я — завершить"_q), [=] {
			box->closeBox();
			review(false);
		}, st::attentionBoxButton);
		box->addButton(rpl::single(u"Это я"_q), [=] {
			box->closeBox();
			review(true);
		});
	}));
}

bool ContainsLoginCode(
		not_null<Main::Session*> session,
		const QString &text) {
	const auto codes = RecentLoginCodes(session);
	if (codes.isEmpty()) {
		return false;
	}
	// Codes are sometimes sent with spaces or dashes: "12 345".
	auto digits = QString();
	for (const auto ch : text) {
		if (ch.isDigit()) {
			digits += ch;
		}
	}
	for (const auto &code : codes) {
		if (text.contains(code) || digits.contains(code)) {
			return true;
		}
	}
	return false;
}

bool GuardLoginCodeSend(
		not_null<Main::Session*> session,
		const QString &text,
		Fn<void()> send) {
	if (Confirmed || !LoginCodeGuard.value() || text.isEmpty()) {
		return false;
	} else if (!ContainsLoginCode(session, text)) {
		return false;
	}
	ShowCodeWarning(std::move(send), false);
	return true;
}

bool GuardLoginCodeForward(
		not_null<Main::Session*> session,
		const std::vector<not_null<HistoryItem*>> &items,
		Fn<void()> forward) {
	if (Confirmed || !LoginCodeGuard.value()) {
		return false;
	}
	const auto service = ServicePeerId();
	const auto dangerous = ranges::any_of(items, [&](
			not_null<HistoryItem*> item) {
		const auto &text = item->originalText().text;
		return (item->history()->peer->id == service
				&& LooksLikeCodeMessage(text)
				&& !CodesIn(text).isEmpty())
			|| ContainsLoginCode(session, text);
	});
	if (!dangerous) {
		return false;
	}
	ShowCodeWarning(std::move(forward), true);
	return true;
}

void SecurityAuditBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller) {
	const auto session = &controller->session();
	box->setTitle(rpl::single(u"Аудит безопасности"_q));
	box->setWidth(st::boxWideWidth);

	const auto password = AddAuditRow(box, u"Облачный пароль (2FA)"_q);
	const auto recovery = AddAuditRow(box, u"Почта для восстановления"_q);
	const auto sessions = AddAuditRow(box, u"Активные сеансы"_q);
	const auto ttl = AddAuditRow(box, u"Автозавершение сеансов"_q);
	const auto phone = AddAuditRow(box, u"Кто видит номер телефона"_q);
	const auto byPhone = AddAuditRow(box, u"Кто может найти по номеру"_q);
	const auto passcode = AddAuditRow(box, u"Локальный код-пароль"_q);
	const auto secgram = AddAuditRow(box, u"Защита SecGram"_q);

	auto &lifetime = box->lifetime();

	session->api().cloudPassword().reload();
	session->api().cloudPassword().state(
	) | rpl::on_next([=](const Core::CloudPasswordState &state) {
		SetAudit(password, state.hasPassword, state.hasPassword
			? u"Включён."_q
			: u"Выключен! Без него код из SMS даёт полный доступ к "
				"аккаунту. Включите: Настройки → Конфиденциальность → "
				"Облачный пароль."_q);
		SetAudit(recovery, state.hasRecovery, state.hasRecovery
			? u"Указана."_q
			: state.hasPassword
			? u"Не указана: забыв пароль, вы потеряете аккаунт."_q
			: u"Сначала включите облачный пароль."_q, true);
	}, lifetime);

	auto &authorizations = session->api().authorizations();
	authorizations.reload();
	authorizations.listValue(
	) | rpl::on_next([=](const Api::Authorizations::List &list) {
		const auto now = base::unixtime::now();
		auto stale = 0;
		auto lines = QStringList();
		for (const auto &entry : list) {
			const auto days = entry.activeTime
				? (now - entry.activeTime) / 86400
				: 0;
			if (days > kStaleSessionDays) {
				++stale;
			}
			lines.push_back(u"• %1, %2 — %3 (%4), активность: %5"_q.arg(
				entry.name,
				entry.platform,
				entry.ip,
				entry.location,
				entry.activeTime
					? base::unixtime::parse(entry.activeTime).toString(
						u"yyyy-MM-dd"_q)
					: u"сейчас"_q));
		}
		auto details = u"Других сеансов: %1."_q.arg(list.size());
		if (stale) {
			details += u" Неактивных больше %1 дней: %2 — завершите их."_q
				.arg(kStaleSessionDays)
				.arg(stale);
		}
		if (!lines.isEmpty()) {
			details += '\n' + lines.join('\n');
		}
		SetAudit(sessions, list.empty() || !stale, details, true);
	}, lifetime);

	authorizations.ttlDays(
	) | rpl::on_next([=](int days) {
		SetAudit(ttl, days > 0 && days <= 183, days > 0
			? u"Через %1 дн. без активности."_q.arg(days)
				+ (days > 183
					? u" Рекомендуем 1–6 месяцев."_q
					: QString())
			: u"Неизвестно."_q, true);
	}, lifetime);

	using Key = Api::UserPrivacy::Key;
	using Option = Api::UserPrivacy::Option;
	const auto optionText = [](Option option) {
		switch (option) {
		case Option::Everyone: return u"все"_q;
		case Option::Contacts: return u"контакты"_q;
		case Option::Nobody: return u"никто"_q;
		default: return u"особые правила"_q;
		}
	};
	auto &privacy = session->api().userPrivacy();
	privacy.reload(Key::PhoneNumber);
	privacy.reload(Key::AddedByPhone);
	privacy.value(
		Key::PhoneNumber
	) | rpl::on_next([=](const Api::UserPrivacy::Rule &rule) {
		SetAudit(
			phone,
			rule.option == Option::Nobody,
			u"Сейчас: "_q + optionText(rule.option)
				+ (rule.option == Option::Nobody
					? QString()
					: u". Рекомендуем «Никто»."_q),
			rule.option == Option::Contacts);
	}, lifetime);
	privacy.value(
		Key::AddedByPhone
	) | rpl::on_next([=](const Api::UserPrivacy::Rule &rule) {
		SetAudit(
			byPhone,
			rule.option != Option::Everyone,
			u"Сейчас: "_q + optionText(rule.option)
				+ (rule.option == Option::Everyone
					? u". По номеру вас может найти любой — "
						"рекомендуем «Контакты»."_q
					: QString()),
			true);
	}, lifetime);

	const auto hasPasscode = Core::App().domain().local().hasLocalPasscode();
	SetAudit(passcode, hasPasscode, hasPasscode
		? u"Установлен."_q
		: u"Не установлен: любой, кто сядет за компьютер, прочитает "
			"переписку. Настройки → Конфиденциальность → Код-пароль."_q,
		true);

	auto off = QStringList();
	const auto check = [&](const char *id, const QString &name) {
		if (!base::options::lookup<bool>(id).value()) {
			off.push_back(name);
		}
	};
	check(kOptionLinkGuard, u"проверка ссылок"_q);
	check(kOptionFileGuard, u"проверка файлов"_q);
	check(kOptionStripMetadata, u"удаление метаданных"_q);
	check(kOptionLoginCodeGuard, u"защита кода входа"_q);
	check(kOptionNewLoginAlert, u"предупреждение о новом входе"_q);
	SetAudit(secgram, off.isEmpty(), off.isEmpty()
		? u"Все основные защиты включены."_q
		: u"Выключено: "_q + off.join(u", "_q) + '.', true);

	box->addButton(rpl::single(u"Сеансы"_q), [=] {
		box->closeBox();
		controller->showSettings(Settings::SessionsId());
	});
	box->addButton(rpl::single(u"Конфиденциальность"_q), [=] {
		box->closeBox();
		controller->showSettings(Settings::PrivacySecurityId());
	});
	box->addLeftButton(tr::lng_close(), [=] { box->closeBox(); });
}

} // namespace SecGram
