#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspection Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

APPLET_ID = "linspectacles-coredumps-inspector"
APPLET_NAME = "Coredumps Inspector"
APPLET_VERSION = "0.0.9"
APPLET_AUTHOR = "brunonlinespace"
APPLET_EDITOR = "brunonlinespace"
APPLET_ORGANIZATION_NAME = "LinSpectacles"
APPLET_ORGANIZATION_ID = "linspectacles"
APPLET_ORGANIZATION_URL = "https://github.com/linspectacles/"
APPLET_REPOSITORY = "https://github.com/linspectacles/coredumps-inspector"

import json
import signal
import subprocess
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QSettings, Qt, QUrl
from PyQt6.QtGui import QColor, QKeySequence, QPixmap, QShortcut, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ._support import BaseInspectorTab, export_records_dialog, metadata_font_qss


def _run(command, timeout=15):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError:
        return "unavailable", None, f"{command[0]} is not installed or not available in PATH."
    except subprocess.TimeoutExpired:
        return "error", None, f"{' '.join(command)} timed out."
    except PermissionError as exc:
        return "restricted", None, str(exc)
    except OSError as exc:
        return "error", None, str(exc)

    if result.returncode == 0:
        return "observed", result, ""
    error_text = (result.stderr or result.stdout or "").strip()
    lowered = error_text.lower()
    if any(term in lowered for term in ("permission denied", "access denied", "not permitted")):
        return "restricted", result, error_text
    return "error", result, error_text or f"Command exited with status {result.returncode}."


def _parse_json_records(text):
    text = (text or "").strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        objects = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                objects.append(value)
            elif isinstance(value, list):
                objects.extend(item for item in value if isinstance(item, dict))
        return objects
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    return []


def _first(obj, *keys, default=""):
    for key in keys:
        if key in obj and obj.get(key) not in (None, ""):
            return obj.get(key)
    # Compatibility with output whose key casing differs.
    lowered = {str(k).lower(): v for k, v in obj.items()}
    for key in keys:
        value = lowered.get(str(key).lower())
        if value not in (None, ""):
            return value
    return default


def _signal_label(value, explicit_name=""):
    explicit_name = str(explicit_name or "").strip()
    if explicit_name:
        return explicit_name
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return str(value or "")
    try:
        return f"{signal.Signals(number).name} ({number})"
    except (ValueError, OSError):
        return str(number)


def _format_time(value):
    if value in (None, ""):
        return ""
    text = str(value).strip()
    try:
        number = int(text)
    except ValueError:
        return text
    # coredumpctl list JSON reports time in microseconds since the Unix epoch.
    try:
        return datetime.fromtimestamp(number / 1_000_000).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    except (OverflowError, OSError, ValueError):
        return text


def _format_size(value):
    if value in (None, ""):
        return ""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return str(value)
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    amount = float(number)
    unit = units[0]
    for candidate in units:
        unit = candidate
        if amount < 1024 or candidate == units[-1]:
            break
        amount /= 1024.0
    if unit == "B":
        return f"{number:,} B"
    return f"{amount:.2f} {unit} ({number:,} B)"


def _normalize(obj):
    raw_time = _first(obj, "time", "COREDUMP_TIMESTAMP", "__REALTIME_TIMESTAMP")
    raw_pid = _first(obj, "pid", "COREDUMP_PID", "_PID")
    raw_sig = _first(obj, "sig", "COREDUMP_SIGNAL")
    sig_name = _first(obj, "signal", "signalname", "SignalName", "COREDUMP_SIGNAL_NAME")
    exe = _first(obj, "exe", "COREDUMP_EXE", "EXE")
    corefile = _first(obj, "corefile", "COREDUMP_FILENAME", default="")
    size = _first(obj, "size", "DiskSize", "COREDUMP_SIZE", default="")
    uid = _first(obj, "uid", "COREDUMP_UID", "_UID")
    gid = _first(obj, "gid", "COREDUMP_GID", "_GID")
    comm = _first(obj, "comm", "COREDUMP_COMM", "_COMM")

    record_label = str(corefile or "").strip()
    if not record_label and size not in (None, ""):
        record_label = _format_size(size)

    return {
        "time": _format_time(raw_time),
        "pid": str(raw_pid or ""),
        "signal": _signal_label(raw_sig, sig_name),
        "executable": str(exe or comm or ""),
        "record": record_label,
        "_raw_time": raw_time,
        "_uid": uid,
        "_gid": gid,
        "_sig": raw_sig,
        "_corefile": corefile,
        "_size": size,
        "_comm": comm,
        "_raw": obj,
    }


def _record_details_plain_text(record):
    lines = [
        f"Time: {record.get('time') or 'Not reported'}",
        f"PID: {record.get('pid') or 'Not reported'}",
        f"Signal: {record.get('signal') or 'Not reported'}",
        f"Executable: {record.get('executable') or 'Not reported'}",
        f"Corefile: {record.get('_corefile') or record.get('record') or 'Not reported'}",
        f"Size: {_format_size(record.get('_size')) or 'Not reported'}",
        f"UID: {record.get('_uid') if record.get('_uid') not in (None, '') else 'Not reported'}",
        f"GID: {record.get('_gid') if record.get('_gid') not in (None, '') else 'Not reported'}",
    ]
    raw = record.get("_raw") or {}
    if raw:
        lines.extend(["", "--- Reported coredumpctl JSON ---"])
        for key in sorted(raw, key=lambda value: str(value).casefold()):
            value = raw.get(key)
            if isinstance(value, (dict, list)):
                shown = json.dumps(value, ensure_ascii=False, sort_keys=True)
            else:
                shown = value
            lines.append(f"{key}: {shown}")
    return "\n".join(lines)


def _sources_text():
    return """Coredumps Inspector is read-only. It lists coredump records visible to the current user through systemd-coredump's coredumpctl interface.

Primary inventory
-----------------
coredumpctl --no-pager --json=short --reverse list

The JSON list format is parsed as the machine-readable coredump inventory. Current systemd list JSON reports presentation fields including time, pid, uid, gid, sig, corefile, exe, and size. Compatibility fallbacks also recognize corresponding COREDUMP_* journal-field names when encountered.

Record details
--------------
The selected record shows normalized inventory fields followed by every key/value returned in that record's coredumpctl JSON object. LinSpectacles does not retrieve or modify the core image itself.

Visibility
----------
coredumpctl can only return records visible through journal access granted to the current user. Records are not assumed to belong to the current boot.

Access model
------------
Read-only. This applet does not delete coredumps, invoke a debugger, dump core images, or alter systemd-coredump configuration.
"""


def _populate_sources_canvas(widget):
    """Render unchanged source notes with the Journal-family Sources presentation."""
    heading_format = QTextCharFormat()
    heading_format.setForeground(QColor("#9cdcfe"))
    heading_format.setFontWeight(600)
    value_format = QTextCharFormat()
    value_format.setForeground(QColor("#dcdcdc"))

    lines = _sources_text().splitlines()
    cursor = widget.textCursor()
    cursor.movePosition(QTextCursor.MoveOperation.Start)
    seen_section = False
    for index, line in enumerate(lines):
        is_heading = (
            bool(line.strip())
            and index + 1 < len(lines)
            and len(lines[index + 1].strip()) >= 3
            and set(lines[index + 1].strip()) == {"-"}
        )
        is_rule = (
            len(line.strip()) >= 3
            and set(line.strip()) == {"-"}
            and index > 0
            and bool(lines[index - 1].strip())
        )
        if is_rule:
            continue  # The coloured heading replaces the old underline rule.
        if is_heading:
            seen_section = True
            cursor.insertText(line + "\n", heading_format)
        elif line:
            cursor.insertText(("  " if seen_section else "") + line + "\n", value_format)
        else:
            cursor.insertText("\n", value_format)
    widget.setTextCursor(cursor)
    widget.moveCursor(QTextCursor.MoveOperation.Start)
    widget.verticalScrollBar().setValue(0)


class CoredumpsOptionsDialog(QDialog):
    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.setWindowTitle("Options — Coredumps Inspector")
        self.resize(980, 720)

        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        appearance_page = QWidget()
        appearance_layout = QVBoxLayout(appearance_page)
        appearance_layout.setContentsMargins(12, 12, 12, 12)
        appearance_layout.setSpacing(10)
        appearance_heading = QLabel("Metadata display")
        font = appearance_heading.font(); font.setBold(True); appearance_heading.setFont(font)
        appearance_layout.addWidget(appearance_heading)
        appearance_note = QLabel(
            "Choose how the inventory and Metadata Details panes are arranged. "
            "This Coredumps Inspector setting is remembered."
        )
        appearance_note.setWordWrap(True)
        appearance_layout.addWidget(appearance_note)
        layout_row = QHBoxLayout()
        layout_row.addWidget(QLabel("Record details layout:"))
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Horizontal", "Vertical"])
        self.layout_combo.setCurrentText("Vertical" if owner.details_orientation == "vertical" else "Horizontal")
        self.layout_combo.currentTextChanged.connect(self._layout_changed)
        layout_row.addWidget(self.layout_combo)
        layout_row.addStretch(1)
        appearance_layout.addLayout(layout_row)

        self.show_metadata_panel = QCheckBox("Show Metadata Details panel (F3)")
        self.show_metadata_panel.setChecked(owner.metadata_panel_visible)
        self.show_metadata_panel.toggled.connect(self._metadata_panel_changed)
        appearance_layout.addWidget(self.show_metadata_panel)

        shortcut_note = QLabel(
            "F3 hides/restores Metadata Details. Ctrl+L toggles Horizontal/Vertical layout. "
            "Shift+F5 refreshes the coredump inventory. Ctrl+/ opens Options."
        )
        shortcut_note.setWordWrap(True)
        appearance_layout.addWidget(shortcut_note)
        appearance_layout.addStretch(1)
        tabs.addTab(appearance_page, "Appearance")

        sources_page = QWidget()
        sources_layout = QVBoxLayout(sources_page)
        sources_layout.setContentsMargins(12, 12, 12, 12)
        sources_layout.setSpacing(10)
        sources_heading = QLabel("Data Sources")
        font = sources_heading.font(); font.setBold(True); font.setPointSize(max(font.pointSize(), 11)); sources_heading.setFont(font)
        sources_layout.addWidget(sources_heading)
        sources_note = QLabel("systemd-coredump interfaces used by this read-only applet.")
        sources_note.setWordWrap(True)
        sources_layout.addWidget(sources_note)
        sources_text = QTextEdit(); sources_text.setReadOnly(True)
        sources_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        chosen_font = getattr(owner, "_metadata_font", None)
        font_rule = ""
        if chosen_font is not None:
            sources_text.setFont(chosen_font); sources_text.document().setDefaultFont(chosen_font); sources_text.setCurrentFont(chosen_font)
            font_rule = metadata_font_qss(chosen_font)
        sources_text.setStyleSheet(
            "QTextEdit { " + font_rule + " background-color: #151719; color: #dcdcdc; border: 1px solid #333333; }"
        )
        _populate_sources_canvas(sources_text)
        sources_layout.addWidget(sources_text, 1)
        tabs.addTab(sources_page, "Sources")

        export_page = QWidget()
        export_layout = QVBoxLayout(export_page)
        export_layout.setContentsMargins(12, 12, 12, 12)
        export_layout.setSpacing(10)
        export_heading = QLabel("Export details")
        font = export_heading.font(); font.setBold(True); export_heading.setFont(font)
        export_layout.addWidget(export_heading)
        export_note = QLabel("Select the Coredumps details to include in the export.")
        export_note.setWordWrap(True)
        export_layout.addWidget(export_note)
        self.export_time = QCheckBox("Time")
        self.export_pid = QCheckBox("PID")
        self.export_signal = QCheckBox("Signal")
        self.export_executable = QCheckBox("Executable")
        self.export_record = QCheckBox("Record")
        self.export_metadata = QCheckBox("Metadata Details")
        for checkbox in (self.export_time, self.export_pid, self.export_signal, self.export_executable, self.export_record):
            checkbox.setChecked(True)
        self.export_metadata.setChecked(False)
        for checkbox in (self.export_time, self.export_pid, self.export_signal, self.export_executable, self.export_record, self.export_metadata):
            export_layout.addWidget(checkbox)
        export_layout.addStretch(1)
        export_row = QHBoxLayout(); export_row.addStretch(1)
        export_button = QPushButton("Export..."); export_button.clicked.connect(self._export_selected)
        export_row.addWidget(export_button); export_layout.addLayout(export_row)
        tabs.addTab(export_page, "Export")

        # About — follows the established LinSpectacles family presentation.
        about = QWidget()
        about_layout = QVBoxLayout(about)
        about_layout.setContentsMargins(24, 20, 24, 18)
        about_layout.setSpacing(8)

        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setFixedSize(112, 112)
        icon_path = Path(__file__).resolve().parent / "icon.png"
        if icon_path.is_file():
            pix = QPixmap(str(icon_path))
            if not pix.isNull():
                icon_label.setPixmap(
                    pix.scaled(
                        112, 112,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                )
        about_layout.addWidget(icon_label, alignment=Qt.AlignmentFlag.AlignHCenter)

        name = QLabel("<h2 style='margin:0'>Coredumps Inspector</h2>")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(name)

        version = QLabel(f"Version {APPLET_VERSION}")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(version)

        slogan = QLabel("<b>Expose. Explore. Explain.</b>")
        slogan.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(slogan)

        desc = QLabel(
            "A read-only LinSpectacles applet for inspecting coredump records "
            "exposed by systemd-coredump."
        )
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(desc)

        details = QLabel(
            "<b>Build:</b> Standalone LinSpectacles applet<br>"
            "<b>Organisation ID:</b> "
            f"<a href='{APPLET_ORGANIZATION_URL}'>{APPLET_ORGANIZATION_ID}</a><br>"
            f"<b>Applet ID:</b> {APPLET_ID}"
        )
        details.setWordWrap(True)
        details.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction
            | Qt.TextInteractionFlag.TextSelectableByMouse
        )
        details.setOpenExternalLinks(True)
        details.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(details)

        copyright_label = QLabel(
            "Copyright © 2026 "
            "<a href='https://github.com/brunonlinespace'>brunonlinespace</a>"
        )
        copyright_label.setOpenExternalLinks(True)
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(copyright_label)

        license_label = QLabel("Licensed under GNU GPLv3 or later.")
        license_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(license_label)

        readme_url = QUrl.fromLocalFile(
            str(Path(__file__).resolve().parent.parent / "README.md")
        ).toString()
        license_url = QUrl.fromLocalFile(
            str(Path(__file__).resolve().parent.parent / "LICENSE")
        ).toString()
        links = QLabel(
            f"<a href='{readme_url}'>README</a> "
            "&nbsp;·&nbsp; "
            f"<a href='{license_url}'>License</a> "
            "&nbsp;·&nbsp; "
            f"<a href='{APPLET_REPOSITORY}'>Repository</a>"
        )
        links.setOpenExternalLinks(True)
        links.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(links)
        about_layout.addStretch(1)
        tabs.addTab(about, "About")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _layout_changed(self, text):
        self.owner.set_details_orientation(str(text).strip().lower(), persist=True)

    def _metadata_panel_changed(self, visible):
        self.owner.set_metadata_panel_visible(visible, persist=True)

    def _export_selected(self):
        selected = []
        if self.export_time.isChecked(): selected.append(("time", "Time", 190, "left"))
        if self.export_pid.isChecked(): selected.append(("pid", "PID", 90, "right"))
        if self.export_signal.isChecked(): selected.append(("signal", "Signal", 110, "left"))
        if self.export_executable.isChecked(): selected.append(("executable", "Executable", 350, "left"))
        if self.export_record.isChecked(): selected.append(("record", "Record", 180, "left"))
        if self.export_metadata.isChecked(): selected.append(("metadata_details", "Metadata Details", 520, "left"))
        if not selected:
            QMessageBox.information(self, "Export", "Select at least one detail to export.")
            return
        records = []
        for record in self.owner.get_export_records():
            item = dict(record)
            if self.export_metadata.isChecked():
                item["metadata_details"] = _record_details_plain_text(record)
            records.append(item)
        if not records:
            QMessageBox.information(self, "Export", "There is no collected data to export.")
            return
        path = export_records_dialog(self, APPLET_NAME, records, columns=selected)
        if path is not None:
            self.owner.set_status(f"Exported data to {path}")


class CoredumpsTab(BaseInspectorTab):
    NUMERIC_COLUMNS = {"pid"}

    def __init__(self, parent=None):
        columns = [
            ("time", "Time", 190, "left"),
            ("pid", "PID", 90, "right"),
            ("signal", "Signal", 110, "left"),
            ("executable", "Executable", 350, "left"),
            ("record", "Record", 180, "left"),
        ]
        super().__init__("Total Coredumps", columns, ["All Signals"], parent)
        self.export_title = APPLET_NAME
        self.search_entry.setPlaceholderText("Search coredump records...")
        self.filter_record_field = "signal"
        self.filter_all_value = "All Signals"
        self.category_label.setText("Signal:")

        self.details_orientation = "horizontal"
        self._load_details_orientation()
        self.metadata_panel_visible = True
        self._metadata_splitter_sizes = None
        self._metadata_splitter_orientation = None
        self._load_metadata_panel_visibility()

        self.export_btn.setText("Options...")
        try:
            self.export_btn.clicked.disconnect()
        except TypeError:
            pass
        self.export_btn.clicked.connect(self.show_options)
        self.export_btn.setEnabled(True)

        self._shortcuts = []
        self._install_shortcuts()
        self.load_modules()

    def show_options(self):
        CoredumpsOptionsDialog(self).exec()

    def _add_shortcut(self, sequence, callback):
        shortcut = QShortcut(QKeySequence(sequence), self)
        shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        shortcut.activated.connect(callback)
        self._shortcuts.append(shortcut)

    def _install_shortcuts(self):
        self._add_shortcut("F3", self.toggle_metadata_panel)
        self._add_shortcut("Ctrl+L", self.toggle_details_orientation)
        self._add_shortcut("Shift+F5", self.load_modules)
        self._add_shortcut("Ctrl+/", self.show_options)

    def toggle_details_orientation(self):
        next_orientation = "vertical" if self.details_orientation == "horizontal" else "horizontal"
        self.set_details_orientation(next_orientation, persist=True)

    def _load_metadata_panel_visibility(self):
        settings = QSettings("brunonlinespace", "Coredumps")
        value = settings.value("metadata_panel_visible", True)
        if isinstance(value, str):
            visible = value.strip().lower() not in {"0", "false", "no", "off"}
        else:
            visible = bool(value)
        self.set_metadata_panel_visible(visible, persist=False)

    def set_metadata_panel_visible(self, visible, *, persist=True):
        visible = bool(visible)
        details_panel = self.splitter.widget(1)
        if details_panel is not None:
            if not visible and self.metadata_panel_visible:
                self._metadata_splitter_sizes = self.splitter.sizes()
                self._metadata_splitter_orientation = self.details_orientation
            details_panel.setVisible(visible)
            if visible and not self.metadata_panel_visible:
                if (self._metadata_splitter_sizes is not None
                        and self._metadata_splitter_orientation == self.details_orientation):
                    self.splitter.setSizes(self._metadata_splitter_sizes)
        self.metadata_panel_visible = visible
        if persist:
            settings = QSettings("brunonlinespace", "Coredumps")
            settings.setValue("metadata_panel_visible", visible)
            settings.sync()

    def toggle_metadata_panel(self):
        self.set_metadata_panel_visible(not self.metadata_panel_visible, persist=True)

    def _load_details_orientation(self):
        settings = QSettings("brunonlinespace", "Coredumps")
        orientation = str(settings.value("details_orientation", "horizontal") or "horizontal").lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.set_details_orientation(orientation, persist=False)

    def set_details_orientation(self, orientation, *, persist=True):
        orientation = str(orientation or "horizontal").lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.details_orientation = orientation
        details_panel = self.splitter.widget(1)
        details_layout = details_panel.layout() if details_panel is not None else None
        if orientation == "vertical":
            self.splitter.setOrientation(Qt.Orientation.Vertical)
            if details_layout is not None: details_layout.setContentsMargins(0, 8, 0, 0)
            self.splitter.setSizes([430, 330])
        else:
            self.splitter.setOrientation(Qt.Orientation.Horizontal)
            if details_layout is not None: details_layout.setContentsMargins(8, 0, 0, 0)
            self.splitter.setSizes([480, 700])
        if persist:
            settings = QSettings("brunonlinespace", "Coredumps")
            settings.setValue("details_orientation", orientation); settings.sync()

    def get_export_records(self):
        return list(self.modules_data)

    def _update_signal_filter(self):
        """List only signal labels present in the latest acquired records."""
        choices = sorted(
            {str(record.get("signal") or "").strip() for record in self.modules_data}
            - {""},
            key=str.casefold,
        )
        previous = self.category_dropdown.currentText()
        was_blocked = self.category_dropdown.blockSignals(True)
        try:
            self.category_dropdown.clear()
            self.category_dropdown.addItem("All Signals")
            self.category_dropdown.addItems(choices)
            self.category_dropdown.setCurrentText(
                previous if previous in choices else "All Signals"
            )
        finally:
            self.category_dropdown.blockSignals(was_blocked)

    def load_modules(self):
        self.modules_data.clear()
        state, result, note = _run(["coredumpctl", "--no-pager", "--json=short", "--reverse", "list"], 20)
        if state == "observed" and result is not None:
            objects = _parse_json_records(result.stdout)
            self.modules_data = [_normalize(obj) for obj in objects]
            self.stats_label.setText(f"{self.total_label_text}: {len(self.modules_data)}")
            self._update_signal_filter()
            self.filter_modules()
            self.clear_info()
            if self.modules_data:
                self.table.selectRow(0)
                self.on_module_select()
                self.set_status(f"Successfully refreshed {len(self.modules_data)} coredump record(s).")
            else:
                self.set_status("No coredump records are visible to the current user.")
            return

        # Older coredumpctl versions may not support JSON output. Preserve a readable
        # fallback rather than pretending the command returned structured records.
        if state == "error" and result is not None and any(
            marker in (result.stderr or "").lower() for marker in ("unrecognized option", "unknown option")
        ):
            fallback_state, fallback, fallback_note = _run(["coredumpctl", "--no-pager", "--no-legend", "--reverse", "list"], 20)
            if fallback_state == "observed" and fallback is not None:
                for line in fallback.stdout.splitlines():
                    line = line.strip()
                    if line:
                        self.modules_data.append({"time":"", "pid":"", "signal":"", "executable":"", "record":line, "_raw":{"plain":line}})
                self.stats_label.setText(f"{self.total_label_text}: {len(self.modules_data)}")
                self._update_signal_filter()
                self.filter_modules(); self.clear_info()
                if self.modules_data:
                    self.table.selectRow(0); self.on_module_select()
                self.set_status(f"Loaded {len(self.modules_data)} coredump record(s) using the plain-list fallback.")
                return
            state, note = fallback_state, fallback_note

        self.stats_label.setText(f"{self.total_label_text}: 0")
        self._update_signal_filter()
        self.filter_modules(); self.clear_info()
        if state == "restricted":
            self.set_status(f"Coredump records are restricted for the current user. {note}".strip())
        elif state == "unavailable":
            self.set_status(note or "coredumpctl is unavailable.")
        else:
            self.set_status(f"Could not read coredump records. {note}".strip())

    def on_module_select(self):
        record = self.current_record()
        if not record:
            return
        self.clear_info()
        self.append_info("--- Coredump Record ---\n")
        self.append_key_value("Time", record.get("time") or "Not reported")
        if record.get("_raw_time") not in (None, ""):
            self.append_key_value("Reported Timestamp (µs)", record.get("_raw_time"))
        self.append_key_value("PID", record.get("pid") or "Not reported")
        self.append_key_value("Signal", record.get("signal") or "Not reported")
        self.append_key_value("Executable", record.get("executable") or "Not reported")
        self.append_key_value("Corefile", record.get("_corefile") or record.get("record") or "Not reported")
        self.append_key_value("Size", _format_size(record.get("_size")) or "Not reported")
        self.append_key_value("UID", record.get("_uid") if record.get("_uid") not in (None, "") else "Not reported")
        self.append_key_value("GID", record.get("_gid") if record.get("_gid") not in (None, "") else "Not reported")

        raw = record.get("_raw") or {}
        if raw:
            self.append_info("\n--- Reported coredumpctl JSON ---\n")
            for key in sorted(raw, key=lambda value: str(value).casefold()):
                value = raw.get(key)
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, ensure_ascii=False, sort_keys=True)
                self.append_key_value(str(key), value)

        cursor = self.info_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.info_text.setTextCursor(cursor)
        self.info_text.verticalScrollBar().setValue(self.info_text.verticalScrollBar().minimum())
        self.set_status(f"Inspecting coredump record for PID {record.get('pid') or 'not reported'}.")


def create_applet(parent=None):
    return CoredumpsTab(parent)
