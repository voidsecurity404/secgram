/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "secgram/secgram_people.h"

#include "base/options.h"
#include "base/timer.h"
#include "base/unixtime.h"
#include "data/data_changes.h"
#include "data/data_peer.h"
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "settings.h"
#include "ui/layers/generic_box.h"
#include "ui/layers/show.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/widgets/labels.h"

#include "styles/style_boxes.h"
#include "styles/style_layers.h"
#include "styles/style_widgets.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>

namespace SecGram {
namespace {

constexpr auto kSaveDelay = 5 * crl::time(1000);
constexpr auto kMaxHistory = 50;

base::options::toggle NameHistoryOption({
	.id = kOptionNameHistory,
	.name = "История имён",
	.description = "Запоминать прежние имена и юзернеймы людей и каналов "
		"(видно в «Информация и ID»). Мошенники часто меняют имя "
		"под «поддержку». Хранится только на этом компьютере.",
	.defaultValue = true,
});

struct State {
	explicit State(not_null<Main::Session*> session)
	: path(cWorkingDir()
		+ u"tdata/secgram/"_q
		+ QString::number(session->userId().bare)
		+ u"/people.json"_q) {
		auto file = QFile(path);
		if (file.open(QIODevice::ReadOnly)) {
			people = QJsonDocument::fromJson(file.readAll()).object();
		}
		saveTimer.setCallback([=] { save(); });
	}

	void save() {
		QDir().mkpath(QFileInfo(path).absolutePath());
		auto file = QFile(path);
		if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
			file.write(QJsonDocument(people).toJson(QJsonDocument::Compact));
		}
	}
	void saveLater() {
		if (!saveTimer.isActive()) {
			saveTimer.callOnce(kSaveDelay);
		}
	}

	QString path;
	QJsonObject people;
	base::Timer saveTimer;
};

std::map<not_null<Main::Session*>, std::unique_ptr<State>> &States() {
	static auto result = std::map<
		not_null<Main::Session*>,
		std::unique_ptr<State>>();
	return result;
}

[[nodiscard]] State *StateFor(not_null<PeerData*> peer) {
	const auto i = States().find(&peer->session());
	return (i != States().end()) ? i->second.get() : nullptr;
}

[[nodiscard]] QString Key(not_null<PeerData*> peer) {
	return QString::number(peer->id.value);
}

void Track(not_null<State*> state, not_null<PeerData*> peer) {
	const auto name = peer->name();
	const auto username = peer->username();
	if (name.isEmpty()) {
		return;
	}
	const auto key = Key(peer);
	auto entry = state->people.value(key).toObject();
	const auto oldName = entry.value(u"name"_q).toString();
	const auto oldUsername = entry.value(u"username"_q).toString();
	if (oldName == name && oldUsername == username) {
		return;
	}
	if (!oldName.isEmpty()) {
		auto history = entry.value(u"history"_q).toArray();
		history.push_back(QJsonObject{
			{ u"at"_q, qint64(base::unixtime::now()) },
			{ u"name"_q, oldName },
			{ u"username"_q, oldUsername },
		});
		while (history.size() > kMaxHistory) {
			history.removeFirst();
		}
		entry.insert(u"history"_q, history);
	}
	entry.insert(u"name"_q, name);
	entry.insert(u"username"_q, username);
	state->people.insert(key, entry);
	state->saveLater();
}

} // namespace

const char kOptionNameHistory[] = "secgram-name-history";

void AttachPeopleTracking(not_null<Main::Session*> session) {
	auto &state = States()[session];
	state = std::make_unique<State>(session);
	const auto raw = state.get();
	using Flag = Data::PeerUpdate::Flag;
	session->changes().peerUpdates(
		Flag::Name | Flag::Username
	) | rpl::on_next([=](const Data::PeerUpdate &update) {
		if (NameHistoryOption.value()) {
			Track(raw, update.peer);
		}
	}, session->lifetime());
	session->lifetime().add([=] {
		const auto i = States().find(session);
		if (i != States().end()) {
			i->second->save();
			States().erase(i);
		}
	});
}

std::vector<NameChange> NameHistory(not_null<PeerData*> peer) {
	auto result = std::vector<NameChange>();
	const auto state = StateFor(peer);
	if (!state) {
		return result;
	}
	const auto entry = state->people.value(Key(peer)).toObject();
	for (const auto &value : entry.value(u"history"_q).toArray()) {
		const auto object = value.toObject();
		result.push_back({
			.at = TimeId(object.value(u"at"_q).toInteger()),
			.name = object.value(u"name"_q).toString(),
			.username = object.value(u"username"_q).toString(),
		});
	}
	return result;
}

QString PeerNote(not_null<PeerData*> peer) {
	const auto state = StateFor(peer);
	return state
		? state->people.value(Key(peer)).toObject().value(
			u"note"_q).toString()
		: QString();
}

void SetPeerNote(not_null<PeerData*> peer, const QString &note) {
	const auto state = StateFor(peer);
	if (!state) {
		return;
	}
	auto entry = state->people.value(Key(peer)).toObject();
	if (note.trimmed().isEmpty()) {
		entry.remove(u"note"_q);
	} else {
		entry.insert(u"note"_q, note.trimmed());
	}
	state->people.insert(Key(peer), entry);
	state->save();
}

void PeerNoteBox(not_null<Ui::GenericBox*> box, not_null<PeerData*> peer) {
	box->setTitle(rpl::single(u"Заметка: "_q + peer->name()));
	box->setWidth(st::boxWideWidth);
	box->addRow(object_ptr<Ui::FlatLabel>(
		box,
		u"Личная заметка о человеке или чате (например «мошенник», "
			"«коллега из SOC», номер инцидента). Видна только вам и "
			"хранится на этом компьютере."_q,
		st::boxDividerLabel));
	box->addSkip(st::boxLittleSkip);
	const auto field = box->addRow(object_ptr<Ui::InputField>(
		box,
		st::defaultInputField,
		Ui::InputField::Mode::MultiLine,
		rpl::single(u"Заметка"_q),
		PeerNote(peer)));
	box->setFocusCallback([=] { field->setFocusFast(); });
	box->addButton(tr::lng_settings_save(), [=] {
		SetPeerNote(peer, field->getLastText());
		box->closeBox();
	});
	box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });
}

} // namespace SecGram
