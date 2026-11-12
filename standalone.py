#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspection Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

import sys
from pathlib import Path

APPLETS_ROOT = Path(__file__).resolve().parent.parent
if str(APPLETS_ROOT) not in sys.path:
    sys.path.insert(0, str(APPLETS_ROOT))

from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication, QMainWindow
from linspectacles_coredumps_inspector.coredumps_inspector.applet import (
    APPLET_NAME, APPLET_ORGANIZATION_ID, APPLET_VERSION, CoredumpsTab
)
from linspectacles_coredumps_inspector.coredumps_inspector._support import STANDALONE_STYLESHEET


def run_standalone():
    app = QApplication(sys.argv)
    app.setApplicationName(APPLET_NAME)
    app.setApplicationVersion(APPLET_VERSION)
    app.setOrganizationName(APPLET_ORGANIZATION_ID)
    app.setStyleSheet(STANDALONE_STYLESHEET)

    win = QMainWindow()
    win.setWindowTitle(f"{APPLET_NAME} {APPLET_VERSION} — LinSpectacles Applet")
    icon_path = Path(__file__).resolve().parent / "coredumps_inspector" / "icon.png"
    if icon_path.is_file():
        icon = QIcon(str(icon_path))
        app.setWindowIcon(icon)
        win.setWindowIcon(icon)
    win.resize(1320, 800)
    win.setCentralWidget(CoredumpsTab())
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(run_standalone())
