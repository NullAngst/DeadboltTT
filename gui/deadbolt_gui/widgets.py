"""Small shared widgets and the painted icons."""

from __future__ import annotations

from PyQt6.QtCore import QPointF, QRectF, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import theme


def rule() -> QFrame:
    f = QFrame()
    f.setObjectName("rule")
    f.setFrameShape(QFrame.Shape.HLine)
    return f


def heading(text: str) -> QLabel:
    lab = QLabel(text)
    f = lab.font()
    f.setPointSizeF(f.pointSizeF() * 1.25)
    f.setBold(True)
    lab.setFont(f)
    return lab


def note(text: str) -> QLabel:
    lab = QLabel(text)
    lab.setWordWrap(True)
    lab.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return lab


class Banner(QWidget):
    """Status banner: one line of reason, one fix button."""

    fix = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.label = QLabel()
        self.label.setObjectName("banner")
        self.label.setWordWrap(True)
        self.button = QPushButton()
        self.button.clicked.connect(lambda: self.fix.emit(self._fix))
        lay.addWidget(self.label, 1)
        lay.addWidget(self.button)
        self._fix = ""
        self.dark = False

    def set(self, level: str, text: str, fix: str, fix_label: str):
        bg = theme.status_colors(self.dark).get(level, theme.status_colors(self.dark)["red"])
        fg = theme.on_color(bg)
        self.label.setStyleSheet(f"QLabel#banner {{ background: {bg}; color: {fg}; }}")
        self.label.setText(text)
        self._fix = fix
        self.button.setVisible(bool(fix))
        self.button.setText(fix_label)


class Tile(QFrame):
    clicked = pyqtSignal()

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setObjectName("tile")
        lay = QVBoxLayout(self)
        t = QLabel(title)
        t.setObjectName("tileTitle")
        self.value = QLabel("...")
        self.value.setWordWrap(True)
        self.detail = QLabel("")
        self.detail.setWordWrap(True)
        self.detail.setEnabled(False)
        lay.addWidget(t)
        lay.addWidget(self.value)
        lay.addWidget(self.detail)
        lay.addStretch(1)
        self.setMinimumHeight(96)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def set(self, value: str, detail: str = "", level: str | None = None, dark: bool = False):
        self.value.setText(value)
        self.detail.setText(detail)
        if level:
            c = theme.status_colors(dark)[level]
            self.value.setStyleSheet(f"color: {c}; font-weight: 600;")
        else:
            self.value.setStyleSheet("")

    def mousePressEvent(self, e):
        self.clicked.emit()
        super().mousePressEvent(e)


def table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    t.verticalHeader().setVisible(False)
    t.horizontalHeader().setStretchLastSection(True)
    t.setAlternatingRowColors(True)
    return t


def fill(t: QTableWidget, rows: list[list[str]], data: list | None = None):
    t.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, val in enumerate(row):
            item = QTableWidgetItem(str(val))
            if data is not None and c == 0:
                item.setData(Qt.ItemDataRole.UserRole, data[r])
            t.setItem(r, c, item)
    t.resizeColumnsToContents()
    t.horizontalHeader().setStretchLastSection(True)


def selected_data(t: QTableWidget):
    rows = sorted({i.row() for i in t.selectedIndexes()})
    out = []
    for r in rows:
        it = t.item(r, 0)
        if it is not None:
            out.append(it.data(Qt.ItemDataRole.UserRole))
    return out


def shield_icon(state: str, size: int = 64, dark: bool = False) -> QIcon:
    """Plain shield, shield with a warning mark, or shield with a cross."""
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    s = size / 64
    path = QPainterPath()
    path.moveTo(32 * s, 4 * s)
    path.lineTo(56 * s, 12 * s)
    path.cubicTo(56 * s, 36 * s, 46 * s, 52 * s, 32 * s, 60 * s)
    path.cubicTo(18 * s, 52 * s, 8 * s, 36 * s, 8 * s, 12 * s)
    path.closeSubpath()
    colors = theme.status_colors(dark)
    fill_c = QColor(
        {"green": colors["green"], "amber": colors["amber"], "red": colors["red"]}.get(state, "#777777")
    )
    p.setPen(QPen(QColor("#1b1b1b") if not dark else QColor("#f0f0f0"), 2.5 * s))
    p.setBrush(fill_c)
    p.drawPath(path)
    mark = QColor(theme.on_color(fill_c.name()))
    p.setPen(QPen(mark, 5 * s, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    if state == "amber":
        p.drawLine(QPointF(32 * s, 18 * s), QPointF(32 * s, 36 * s))
        p.drawPoint(QPointF(32 * s, 46 * s))
    elif state == "red":
        p.drawLine(QPointF(23 * s, 22 * s), QPointF(41 * s, 42 * s))
        p.drawLine(QPointF(41 * s, 22 * s), QPointF(23 * s, 42 * s))
    else:
        p.drawLine(QPointF(22 * s, 32 * s), QPointF(29 * s, 40 * s))
        p.drawLine(QPointF(29 * s, 40 * s), QPointF(43 * s, 24 * s))
    p.end()
    return QIcon(pm)


def app_icon(dark: bool = False) -> QIcon:
    themed = QIcon.fromTheme("deadbolt")
    if not themed.isNull():
        return themed
    pm = QPixmap(128, 128)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QColor(theme.copper(dark)))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(QRectF(8, 8, 112, 112), 24, 24)
    p.setBrush(QColor("#ffffff"))
    p.drawRoundedRect(QRectF(36, 58, 56, 44), 6, 6)
    p.setPen(QPen(QColor("#ffffff"), 9))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawArc(QRectF(44, 26, 40, 48), 0, 180 * 16)
    p.end()
    return QIcon(pm)
