/*
This file is part of SecGram, a security-focused Telegram Desktop fork.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "secgram/secgram_tools.h"

#include "base/unixtime.h"
#include "core/file_utilities.h"
#include "data/data_peer.h"
#include "data/data_session.h"
#include "history/history.h"
#include "history/history_item.h"
#include "history/view/history_view_element.h"
#include "lang/lang_keys.h"
#include "main/main_session.h"
#include "secgram/secgram_analyzer.h"
#include "secgram/secgram_intel.h"
#include "settings.h"
#include "ui/layers/generic_box.h"
#include "ui/layers/show.h"
#include "ui/text/text_utilities.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/widgets/labels.h"
#include "ui/wrap/vertical_layout.h"
#include "window/window_session_controller.h"

#include "styles/style_boxes.h"
#include "styles/style_layers.h"
#include "styles/style_widgets.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QProcess>
#include <QtCore/QRegularExpression>
#include <QtCore/QSet>
#include <QtCore/QStandardPaths>
#include <QtCore/QSysInfo>
#include <QtGui/QClipboard>
#include <QtGui/QGuiApplication>

namespace SecGram {
namespace {

constexpr auto kMaxSearchResults = 200;

[[nodiscard]] QString Root() {
	return cWorkingDir() + u"tdata/secgram/"_q;
}

[[nodiscard]] QString AccountRoot(not_null<Main::Session*> session) {
	return Root() + QString::number(session->userId().bare) + '/';
}

[[nodiscard]] QString ReadText(const QString &path) {
	auto file = QFile(path);
	return file.open(QIODevice::ReadOnly)
		? QString::fromUtf8(file.readAll())
		: QString();
}

void WriteText(const QString &path, const QString &text) {
	QDir().mkpath(QFileInfo(path).absolutePath());
	auto file = QFile(path);
	if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
		file.write(text.toUtf8());
	}
}

// Cached sets of peer ids, one file per kind and account.
QSet<QString> &PeerSet(const QString &path) {
	static auto cache = std::map<QString, QSet<QString>>();
	const auto i = cache.find(path);
	if (i != cache.end()) {
		return i->second;
	}
	auto set = QSet<QString>();
	for (const auto &line : ReadText(path).split('\n')) {
		if (!line.trimmed().isEmpty()) {
			set.insert(line.trimmed());
		}
	}
	return cache.emplace(path, std::move(set)).first->second;
}

void TogglePeer(const QString &path, not_null<PeerData*> peer, bool on) {
	auto &set = PeerSet(path);
	const auto key = QString::number(peer->id.value);
	if (on) {
		set.insert(key);
	} else {
		set.remove(key);
	}
	WriteText(path, QStringList(set.begin(), set.end()).join('\n'));
}

[[nodiscard]] QString GhostPath(not_null<Main::Session*> session) {
	return AccountRoot(session) + u"ghost_chats.txt"_q;
}

[[nodiscard]] QString CollectPath(not_null<Main::Session*> session) {
	return AccountRoot(session) + u"ioc_chats.txt"_q;
}

[[nodiscard]] QString TemplatesPath() {
	return Root() + u"templates.txt"_q;
}

[[nodiscard]] QStringList DefaultTemplates() {
	return {
		u"⚠️ Это фишинговая ссылка. Не открывайте её и не вводите "
			"никаких данных. Если уже ввели — срочно смените пароль и "
			"сообщите в отдел информационной безопасности."_q,
		u"Никому не сообщайте код из SMS или Telegram. Сотрудники банка, "
			"поддержки и «службы безопасности» никогда его не спрашивают."_q,
		u"Этот файл опасен (вредоносная программа). Не открывайте его, "
			"удалите и сообщите в отдел ИБ."_q,
		u"Спасибо за сообщение! Инцидент зарегистрирован под номером "
			"#INC-"_q,
		u"Включите облачный пароль: Настройки → Конфиденциальность "
			"→ Облачный пароль. Проверьте активные сеансы и завершите "
			"незнакомые."_q,
	};
}

[[nodiscard]] QStringList Templates() {
	const auto text = ReadText(TemplatesPath());
	if (text.trimmed().isEmpty()) {
		return DefaultTemplates();
	}
	auto result = QStringList();
	for (const auto &part : text.split(u"\n---\n"_q)) {
		if (!part.trimmed().isEmpty()) {
			result.push_back(part.trimmed());
		}
	}
	return result;
}

void RunTool(
		const QString &program,
		const QStringList &arguments,
		Fn<void(QString)> done) {
	const auto process = new QProcess(qApp);
	QObject::connect(
		process,
		&QProcess::finished,
		[=](int code, QProcess::ExitStatus) {
			auto output = QString::fromUtf8(
				process->readAllStandardOutput()).trimmed();
			const auto error = QString::fromUtf8(
				process->readAllStandardError()).trimmed();
			if (output.isEmpty() && !error.isEmpty()) {
				output = error;
			}
			process->deleteLater();
			done(output.isEmpty()
				? u"(код выхода %1, вывода нет)"_q.arg(code)
				: output);
		});
	QObject::connect(process, &QProcess::errorOccurred, [=](
			QProcess::ProcessError) {
		if (process->state() == QProcess::NotRunning) {
			done(u"Не удалось запустить "_q + program);
			process->deleteLater();
		}
	});
	process->start(program, arguments);
}

} // namespace

bool ClamAvAvailable() {
	return !QStandardPaths::findExecutable(u"clamscan"_q).isEmpty();
}

QString YaraRulesFolder() {
	return Root() + u"yara"_q;
}

bool YaraAvailable() {
	if (QStandardPaths::findExecutable(u"yara"_q).isEmpty()) {
		return false;
	}
	const auto rules = QDir(YaraRulesFolder()).entryList(
		{ u"*.yar"_q, u"*.yara"_q },
		QDir::Files);
	return !rules.isEmpty();
}

bool SandboxAvailable() {
	return !QStandardPaths::findExecutable(u"firejail"_q).isEmpty();
}

void ScanWithClamAv(const QString &path, Fn<void(QString)> done) {
	RunTool(
		u"clamscan"_q,
		{ u"--no-summary"_q, u"--infected"_q, path },
		[=](QString output) {
			done(output.contains(u"FOUND"_q)
				? (u"\U0001F534 ClamAV: "_q + output)
				: output.startsWith(u"(код выхода 0"_q)
				? u"✅ ClamAV: угроз не найдено"_q
				: (u"ClamAV: "_q + output));
		});
}

void ScanWithYara(const QString &path, Fn<void(QString)> done) {
	const auto folder = QDir(YaraRulesFolder());
	auto arguments = QStringList{ u"-w"_q };
	for (const auto &rule : folder.entryList(
			{ u"*.yar"_q, u"*.yara"_q },
			QDir::Files)) {
		arguments.push_back(folder.filePath(rule));
	}
	arguments.push_back(path);
	RunTool(u"yara"_q, arguments, [=](QString output) {
		done(output.startsWith(u"(код выхода 0"_q)
			? u"✅ YARA: совпадений нет"_q
			: (u"\U0001F7E0 YARA: "_q + output));
	});
}

void OpenInSandbox(const QString &path) {
	QProcess::startDetached(
		u"firejail"_q,
		{ u"--net=none"_q, u"--noroot"_q, u"xdg-open"_q, path });
}

bool GhostReadChat(not_null<PeerData*> peer) {
	return PeerSet(GhostPath(&peer->session())).contains(
		QString::number(peer->id.value));
}

void SetGhostReadChat(not_null<PeerData*> peer, bool enabled) {
	TogglePeer(GhostPath(&peer->session()), peer, enabled);
}

bool CollectIocsChat(not_null<PeerData*> peer) {
	return PeerSet(CollectPath(&peer->session())).contains(
		QString::number(peer->id.value));
}

void SetCollectIocsChat(not_null<PeerData*> peer, bool enabled) {
	TogglePeer(CollectPath(&peer->session()), peer, enabled);
}

QString IocFeedPath(not_null<Main::Session*> session) {
	return AccountRoot(session) + u"ioc_feed.csv"_q;
}

void CollectIocs(not_null<HistoryItem*> item) {
	const auto peer = item->history()->peer;
	if (!CollectIocsChat(peer)) {
		return;
	}
	const auto iocs = ExtractIocs(item->originalText().text);
	if (iocs.empty()) {
		return;
	}
	const auto path = IocFeedPath(&peer->session());
	const auto exists = QFile::exists(path);
	QDir().mkpath(QFileInfo(path).absolutePath());
	auto file = QFile(path);
	if (!file.open(QIODevice::WriteOnly | QIODevice::Append)) {
		return;
	}
	if (!exists) {
		file.write("date_utc,chat,message_id,type,value\n");
	}
	const auto date = base::unixtime::parse(item->date()).toUTC().toString(
		Qt::ISODate);
	auto chat = peer->name();
	chat.replace('"', u"\"\""_q);
	for (const auto &ioc : iocs) {
		auto value = ioc.value;
		value.replace('"', u"\"\""_q);
		file.write(u"%1,\"%2\",%3,%4,\"%5\"\n"_q.arg(
			date,
			chat,
			QString::number(item->id.bare),
			IocTypeName(ioc.type),
			value).toUtf8());
	}
}

void AppendCustody(
		const QString &folder,
		int messages,
		const QString &manifestSha256) {
	const auto path = Root() + u"custody.log"_q;
	QDir().mkpath(QFileInfo(path).absolutePath());
	auto file = QFile(path);
	if (file.open(QIODevice::WriteOnly | QIODevice::Append)) {
		file.write(u"%1\t%2\t%3\tmessages=%4\tmanifest_sha256=%5\n"_q.arg(
			QDateTime::currentDateTimeUtc().toString(Qt::ISODate),
			QSysInfo::machineHostName() + '/' + qEnvironmentVariable("USER"),
			folder,
			QString::number(messages),
			manifestSha256).toUtf8());
	}
}

void ExportTeamConfig(std::shared_ptr<Ui::Show> show) {
	FileDialog::GetWritePath(
		nullptr,
		u"Экспорт настроек SecGram для команды"_q,
		u"JSON (*.json)"_q,
		QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation)
			+ u"/secgram-team.json"_q,
		[=](QString &&path) {
			const auto object = QJsonObject{
				{ u"secgram_team"_q, 1 },
				{ u"watchlist"_q, ReadText(Root() + u"watchlist.txt"_q) },
				{ u"domains"_q, ReadText(Root() + u"domains.txt"_q) },
				{ u"templates"_q, QJsonArray::fromStringList(Templates()) },
			};
			WriteText(path, QString::fromUtf8(
				QJsonDocument(object).toJson(QJsonDocument::Indented)));
			show->showToast(u"Сохранено: "_q + path);
		});
}

void ImportTeamConfig(std::shared_ptr<Ui::Show> show) {
	FileDialog::GetOpenPath(
		nullptr,
		u"Импорт настроек SecGram"_q,
		u"JSON (*.json)"_q,
		[=](FileDialog::OpenResult &&result) {
			if (result.paths.isEmpty()) {
				return;
			}
			const auto object = QJsonDocument::fromJson(
				ReadText(result.paths.front()).toUtf8()).object();
			if (!object.contains(u"secgram_team"_q)) {
				show->showToast(u"Это не файл настроек SecGram."_q);
				return;
			}
			// Lists are merged, so own entries are kept.
			const auto merge = [](const QString &path, const QString &add) {
				auto lines = ReadText(path).split('\n');
				for (const auto &line : add.split('\n')) {
					if (!line.trimmed().isEmpty() && !lines.contains(line)) {
						lines.push_back(line);
					}
				}
				WriteText(path, lines.join('\n').trimmed() + '\n');
			};
			merge(
				Root() + u"watchlist.txt"_q,
				object.value(u"watchlist"_q).toString());
			merge(
				Root() + u"domains.txt"_q,
				object.value(u"domains"_q).toString());
			auto templates = Templates();
			for (const auto &value : object.value(u"templates"_q).toArray()) {
				if (!templates.contains(value.toString())) {
					templates.push_back(value.toString());
				}
			}
			WriteText(TemplatesPath(), templates.join(u"\n---\n"_q));
			ReloadIntelLists();
			show->showToast(u"Настройки команды импортированы."_q);
		});
}

void TemplatesBox(not_null<Ui::GenericBox*> box) {
	box->setTitle(rpl::single(u"Шаблоны ответов"_q));
	box->setWidth(st::boxWideWidth);
	box->addRow(object_ptr<Ui::FlatLabel>(
		box,
		u"Нажмите на шаблон, чтобы скопировать его, и вставьте в чат "
			"(Ctrl+V). Ниже можно отредактировать список — шаблоны "
			"разделяются строкой из трёх дефисов (---)."_q,
		st::boxDividerLabel));
	const auto show = box->uiShow();
	for (const auto &text : Templates()) {
		box->addSkip(st::boxLittleSkip);
		const auto label = box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			rpl::single(Ui::Text::Link(text, u"internal:secgram_tpl"_q)),
			st::boxLabel));
		label->setClickHandlerFilter([=](const auto &...) {
			QGuiApplication::clipboard()->setText(text);
			show->showToast(u"Скопировано — вставьте в чат"_q);
			return false;
		});
	}
	box->addSkip(st::boxLittleSkip);
	const auto field = box->addRow(object_ptr<Ui::InputField>(
		box,
		st::defaultInputField,
		Ui::InputField::Mode::MultiLine,
		rpl::single(u"Шаблоны"_q),
		Templates().join(u"\n---\n"_q)));
	box->addButton(tr::lng_settings_save(), [=] {
		WriteText(TemplatesPath(), field->getLastText());
		box->closeBox();
	});
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
}

void RegexSearchBox(
		not_null<Ui::GenericBox*> box,
		not_null<Window::SessionController*> controller,
		not_null<History*> history) {
	box->setTitle(rpl::single(u"Поиск по регулярному выражению"_q));
	box->setWidth(st::boxWideWidth);
	box->addRow(object_ptr<Ui::FlatLabel>(
		box,
		u"Ищет по загруженным сообщениям этого чата (прокрутите историю "
			"вверх, чтобы загрузить больше). Пример: "
			"\\b\\d{16}\\b — номера карт, (?i)парол|parol."_q,
		st::boxDividerLabel));
	const auto field = box->addRow(object_ptr<Ui::InputField>(
		box,
		st::defaultInputField,
		rpl::single(u"Регулярное выражение"_q)));
	const auto results = box->addRow(object_ptr<Ui::VerticalLayout>(box));
	const auto search = [=] {
		results->clear();
		const auto re = QRegularExpression(field->getLastText());
		if (!re.isValid() || field->getLastText().isEmpty()) {
			results->add(object_ptr<Ui::FlatLabel>(
				results,
				u"Некорректное выражение: "_q + re.errorString(),
				st::boxLabel));
			results->resizeToWidth(box->width());
			return;
		}
		auto found = 0;
		for (auto b = history->blocks.rbegin();
				b != history->blocks.rend() && found < kMaxSearchResults;
				++b) {
			const auto &messages = (*b)->messages;
			for (auto m = messages.rbegin();
					m != messages.rend() && found < kMaxSearchResults;
					++m) {
				const auto item = (*m)->data();
				const auto &text = item->originalText().text;
				const auto match = re.match(text);
				if (!match.hasMatch()) {
					continue;
				}
				++found;
				const auto id = item->id;
				auto line = TextWithEntities{
					base::unixtime::parse(item->date()).toString(
						u"yyyy-MM-dd HH:mm  "_q)
					+ item->from()->name() + u": "_q,
				};
				const auto from = std::max(qsizetype(0), match.capturedStart() - 40);
				line.append(Ui::Text::Link(
					text.mid(from, 160).replace('\n', ' '),
					u"internal:secgram_jump"_q));
				const auto label = results->add(object_ptr<Ui::FlatLabel>(
					results,
					rpl::single(line),
					st::boxLabel));
				label->setClickHandlerFilter([=](const auto &...) {
					box->closeBox();
					controller->showPeerHistory(
						history,
						Window::SectionShow::Way::Forward,
						id);
					return false;
				});
			}
		}
		if (!found) {
			results->add(object_ptr<Ui::FlatLabel>(
				results,
				u"Ничего не найдено в загруженных сообщениях."_q,
				st::boxLabel));
		}
		results->resizeToWidth(box->width()
			- st::boxRowPadding.left()
			- st::boxRowPadding.right());
	};
	field->submits() | rpl::on_next([=](auto) { search(); }, field->lifetime());
	box->setFocusCallback([=] { field->setFocusFast(); });
	box->addButton(rpl::single(u"Искать"_q), search);
	box->addButton(tr::lng_close(), [=] { box->closeBox(); });
}

} // namespace SecGram
