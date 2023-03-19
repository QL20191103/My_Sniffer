# coding=utf-8
import os
import sys
import time
from queue import Queue

from scapy import all as cap
from scapy.layers.inet import IP
from scapy.all import Padding
from scapy.all import Raw
from scapy.utils import hexdump
from scapy.arch.common import compile_filter

from PySide6 import QtWidgets
from PySide6 import QtGui
from PySide6 import QtCore
from PySide6.QtWidgets import QTableWidgetItem as QTItem
from PySide6.QtWidgets import QListWidgetItem as QLItem
from PySide6.QtWidgets import QTreeWidgetItem as QRItem

from PySide6.QtWidgets import QMainWindow
from ui import main as main_ui
from ui import about as about_ui
from logger import logger

DIRNAME = os.path.dirname(os.path.abspath(__file__))
VERSION = "0.0.1"
MAXSIZE = 1024
LOGO = os.path.join(DIRNAME, 'images/logo.png')


class Signal(QtCore.QObject):

    recv = QtCore.Signal(None)


class MainWindow(QMainWindow):

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        # 将ui文件转化为py文件，将主窗口设置成main.ui
        self.myui = main_ui.Ui_MainWindow()
        self.myui.setupUi(self)
        # 嗅探器
        self.mysniffer = None
        # 包的数量
        self.mycount = 0
        # 开始抓包的时间
        self.start_time = 0
        # QT的通信方式，子线程向主线程通信的方式，对于UI的操作只能在主线程中进行
        self.signal = Signal()
        # 队列用来存放包
        self.queue = Queue()
        # about窗口
        self.myabout = None
        # 设置窗口的标题
        self.setWindowTitle(f"Sniffer v{VERSION}")
        # 设置窗口的图标
        self.setWindowIcon(QtGui.QIcon(LOGO))
        # 初始化interface
        self.init_interfaces()

    def init_interfaces(self):
        # 找到当前所有可用的网卡设备
        for face in cap.get_working_ifaces():
            # 将可用网卡添加到网卡的下拉框里
            self.myui.interfaceBox.addItem(face.name)

        # todo remove after test
        # self.myui.interfaceBox.setCurrentIndex(4)
        # 将startButton连接到start_click，也就是点击startButton触发点击事件
        self.myui.startButton.clicked.connect(self.start_click)
        # 监听BPF表达式，并验证是否正确
        self.myui.filterEdit.editingFinished.connect(self.validate_filter)
        # 将表头影藏
        self.myui.packetTable.horizontalHeader().setStretchLastSection(True)
        # 点击后更新二进制的输出窗口，以及层的信息
        self.myui.packetTable.cellPressed.connect(self.update_content)
        self.myui.treeWidget.itemPressed.connect(self.update_layer_content)
        # 收到包之后更新update_packet
        self.signal.recv.connect(self.update_packet)
        # 点击about显示about窗口
        self.myui.actionAbout.triggered.connect(self.show_about)

    def show_about(self):
        # 有的话直接显示
        if self.myabout:
            self.myabout.show()
            return
        # 没有的话，新建一个再显示
        self.myabout = QtWidgets.QDialog(self)
        self.myabout.ui = about_ui.Ui_Dialog()
        self.myabout.ui.setupUi(self.myabout)
        self.myabout.ui.version_label.setText(f"Sniffer v{VERSION}")
        self.myabout.ui.image_label.setPixmap(QtGui.QPixmap(LOGO))
        self.myabout.ui.image_label.setScaledContents(True)
        self.myabout.show()

    # 获取当前下拉框选择的网卡设备
    def get_iface(self):
        idx = self.myui.interfaceBox.currentIndex()
        iface = cap.get_working_ifaces()[idx]
        return iface
    # 验证BPF表达式是否正确
    def validate_filter(self):
        exp = self.myui.filterEdit.text().strip()
        # 为空直接返回TRUE
        if not exp:
            self.myui.filterEdit.setStyleSheet('')
            self.myui.startButton.setEnabled(True)
            return

        try:
            compile_filter(filter_exp=exp)
            # 输入框背景变绿，start可以点击
            self.myui.filterEdit.setStyleSheet('QLineEdit { background-color: rgb(33, 186, 69);}')
            self.myui.startButton.setEnabled(True)
        except Exception:
            # 将输入框背景变红，start不可点击
            self.myui.startButton.setEnabled(False)
            self.myui.filterEdit.setStyleSheet('QLineEdit { background-color: rgb(219, 40, 40);}')
            return
    # 迭代package不同层之间的包，并返回
    def get_packet_layers(self, packet):
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            yield layer
            counter += 1
    # 更新layer_content的输入框
    def update_layer_content(self, item, column):
        if not hasattr(item, 'layer'):
            return
        layer = item.layer
        self.myui.contentEdit.setText(hexdump(layer, dump=True))
    # 更新包的信息
    def update_content(self, x, y):
        logger.debug("%s, %s clicked", x, y)
        item = self.myui.packetTable.item(x, 6)
        if not hasattr(item, 'packet'):
            return
        logger.debug(item)
        logger.debug(item.text())
        packet = item.packet
        self.myui.contentEdit.setText(hexdump(packet, dump=True))
        # 点击后更新树状图的信息
        self.myui.treeWidget.clear()
        for layer in self.get_packet_layers(packet):
            item = QRItem(self.myui.treeWidget)
            item.layer = layer
            item.setText(0, layer.name)
            # self.myui.treeWidget.addTopLevelItem(item)

            for name, value in layer.fields.items():
                child = QRItem(item)
                child.setText(0, f"{name}: {value}")

        # self.myui.treeWidget.expandAll()

    # 收到qt信号后调用update_packet
    def update_packet(self):
        packet = self.queue.get(False)
        if not packet:
            return
        # 检测package的数量是不是大于MAXSIZE
        if self.myui.packetTable.rowCount() >= MAXSIZE:
            # 去掉最开始进入的包
            self.myui.packetTable.removeRow(0)
        # 插入新的包，并将包的信息插入表格
        row = self.myui.packetTable.rowCount()
        self.myui.packetTable.insertRow(row)

        # No.
        self.mycount += 1
        self.myui.packetTable.setItem(row, 0, QTItem(str(self.mycount)))

        # Time
        elapse = time.time() - self.start_time
        self.myui.packetTable.setItem(row, 1, QTItem(f"{elapse:2f}"))

        # source
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
        else:
            src = packet.src
            dst = packet.dst

        self.myui.packetTable.setItem(row, 2, QTItem(src))

        # destination
        self.myui.packetTable.setItem(row, 3, QTItem(dst))

        # protocol
        layer = None
        for var in self.get_packet_layers(packet):
            if not isinstance(var, (Padding, Raw)):
                layer = var

        protocol = layer.name
        self.myui.packetTable.setItem(row, 4, QTItem(str(protocol)))

        # length
        length = f"{len(packet)}"
        self.myui.packetTable.setItem(row, 5, QTItem(length))

        # info

        info = str(packet.summary())
        item = QTItem(info)
        item.packet = packet
        self.myui.packetTable.setItem(row, 6, item)
        # input()
        # logger.debug(pkg)
    # 将捕获到的package压入队列
    def sniff_action(self, packet):
        if not self.mysniffer:
            return
        self.queue.put(packet)
        # 调用qt信号
        self.signal.recv.emit()

    def start_click(self):
        logger.debug("start button was clicked")
        # 停止抓包
        if self.mysniffer:
            self.mysniffer.stop()
            self.mysniffer = None
            self.myui.startButton.setText("Start")
            self.myui.interfaceBox.setEnabled(True)
            self.myui.filterEdit.setEnabled(True)
            return
        # 找到BPF表达式
        exp = self.myui.filterEdit.text()
        logger.debug("filter expression %s", exp)
        # 找到interface
        iface = self.get_iface()
        logger.debug("sniffing interface %s", iface)
        # 新建一个sniffer
        self.mysniffer = cap.AsyncSniffer(
            iface=iface,
            # 当捕获到一个包之后，就会调用sniff_action
            prn=self.sniff_action,
            filter=exp,
        )
        # 开始sniffer
        self.mysniffer.start()
        self.mycount = 0
        self.start_time = time.time()
        # 初始化设置
        self.myui.startButton.setText("Stop")
        self.myui.interfaceBox.setEnabled(False)
        self.myui.filterEdit.setEnabled(False)
        self.myui.packetTable.clearContents()
        self.myui.packetTable.setRowCount(0)
        self.myui.treeWidget.clear()
        self.myui.contentEdit.clear()


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
