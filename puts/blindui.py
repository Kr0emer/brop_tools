# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file './untitled.ui'
#
# Created by: PyQt5 UI code generator 5.14.1
#
# WARNING! All changes made in this file will be lost!


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(777, 647)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(50, 120, 150, 30))
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(50, 170, 150, 30))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(50, 220, 141, 30))
        self.label_3.setObjectName("label_3")
        self.start_str = QtWidgets.QLineEdit(self.centralwidget)
        self.start_str.setGeometry(QtCore.QRect(200, 120, 500, 30))
        self.start_str.setText("")
        self.start_str.setObjectName("start_str")
        self.end_start = QtWidgets.QLineEdit(self.centralwidget)
        self.end_start.setGeometry(QtCore.QRect(200, 170, 500, 30))
        self.end_start.setText("")
        self.end_start.setObjectName("end_start")
        self.elf_load = QtWidgets.QLineEdit(self.centralwidget)
        self.elf_load.setGeometry(QtCore.QRect(200, 220, 200, 30))
        self.elf_load.setWhatsThis("")
        self.elf_load.setText("")
        self.elf_load.setObjectName("elf_load")
        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setGeometry(QtCore.QRect(50, 20, 43, 30))
        self.label_4.setObjectName("label_4")
        self.label_5 = QtWidgets.QLabel(self.centralwidget)
        self.label_5.setGeometry(QtCore.QRect(264, 20, 60, 30))
        self.label_5.setObjectName("label_5")
        self.ip = QtWidgets.QLineEdit(self.centralwidget)
        self.ip.setGeometry(QtCore.QRect(106, 20, 142, 30))
        self.ip.setText("")
        self.ip.setObjectName("ip")
        self.port = QtWidgets.QLineEdit(self.centralwidget)
        self.port.setGeometry(QtCore.QRect(328, 20, 109, 30))
        self.port.setText("")
        self.port.setObjectName("port")
        self.label_6 = QtWidgets.QLabel(self.centralwidget)
        self.label_6.setGeometry(QtCore.QRect(50, 70, 150, 30))
        self.label_6.setObjectName("label_6")
        self.dumpfile = QtWidgets.QLineEdit(self.centralwidget)
        self.dumpfile.setGeometry(QtCore.QRect(200, 70, 400, 30))
        self.dumpfile.setText("")
        self.dumpfile.setObjectName("dumpfile")
        self.label_7 = QtWidgets.QLabel(self.centralwidget)
        self.label_7.setGeometry(QtCore.QRect(50, 270, 141, 30))
        self.label_7.setObjectName("label_7")
        self.off = QtWidgets.QLineEdit(self.centralwidget)
        self.off.setGeometry(QtCore.QRect(200, 270, 109, 30))
        self.off.setText("")
        self.off.setObjectName("off")
        self.off_b = QtWidgets.QPushButton(self.centralwidget)
        self.off_b.setGeometry(QtCore.QRect(380, 270, 89, 25))
        self.off_b.setObjectName("off_b")
        self.label_8 = QtWidgets.QLabel(self.centralwidget)
        self.label_8.setGeometry(QtCore.QRect(50, 320, 151, 30))
        self.label_8.setObjectName("label_8")
        self.stop = QtWidgets.QLineEdit(self.centralwidget)
        self.stop.setGeometry(QtCore.QRect(200, 320, 200, 30))
        self.stop.setWhatsThis("")
        self.stop.setText("")
        self.stop.setObjectName("stop")
        self.stop_b = QtWidgets.QPushButton(self.centralwidget)
        self.stop_b.setGeometry(QtCore.QRect(460, 320, 89, 25))
        self.stop_b.setObjectName("stop_b")
        self.label_9 = QtWidgets.QLabel(self.centralwidget)
        self.label_9.setGeometry(QtCore.QRect(50, 370, 161, 30))
        self.label_9.setObjectName("label_9")
        self.brop = QtWidgets.QLineEdit(self.centralwidget)
        self.brop.setGeometry(QtCore.QRect(200, 370, 200, 30))
        self.brop.setWhatsThis("")
        self.brop.setText("")
        self.brop.setObjectName("brop")
        self.brop_b = QtWidgets.QPushButton(self.centralwidget)
        self.brop_b.setGeometry(QtCore.QRect(460, 370, 89, 21))
        self.brop_b.setObjectName("brop_b")
        self.label_10 = QtWidgets.QLabel(self.centralwidget)
        self.label_10.setGeometry(QtCore.QRect(50, 420, 121, 30))
        self.label_10.setObjectName("label_10")
        self.plt_maybe = QtWidgets.QLineEdit(self.centralwidget)
        self.plt_maybe.setGeometry(QtCore.QRect(200, 420, 200, 30))
        self.plt_maybe.setWhatsThis("")
        self.plt_maybe.setText("")
        self.plt_maybe.setObjectName("plt_maybe")
        self.plt_b = QtWidgets.QPushButton(self.centralwidget)
        self.plt_b.setGeometry(QtCore.QRect(460, 420, 89, 21))
        self.plt_b.setObjectName("plt_b")
        self.label_11 = QtWidgets.QLabel(self.centralwidget)
        self.label_11.setGeometry(QtCore.QRect(50, 470, 121, 30))
        self.label_11.setObjectName("label_11")
        self.puts_addr = QtWidgets.QLineEdit(self.centralwidget)
        self.puts_addr.setGeometry(QtCore.QRect(200, 470, 200, 30))
        self.puts_addr.setWhatsThis("")
        self.puts_addr.setText("")
        self.puts_addr.setObjectName("puts_addr")
        self.puts_b = QtWidgets.QPushButton(self.centralwidget)
        self.puts_b.setGeometry(QtCore.QRect(460, 470, 89, 21))
        self.puts_b.setObjectName("puts_b")
        self.dump_b = QtWidgets.QPushButton(self.centralwidget)
        self.dump_b.setGeometry(QtCore.QRect(640, 560, 89, 21))
        self.dump_b.setObjectName("dump_b")
        self.label_12 = QtWidgets.QLabel(self.centralwidget)
        self.label_12.setGeometry(QtCore.QRect(50, 520, 121, 30))
        self.label_12.setObjectName("label_12")
        self.one_strs = QtWidgets.QLineEdit(self.centralwidget)
        self.one_strs.setGeometry(QtCore.QRect(200, 520, 200, 30))
        self.one_strs.setWhatsThis("")
        self.one_strs.setText("")
        self.one_strs.setObjectName("one_strs")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 777, 28))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.action = QtWidgets.QAction(MainWindow)
        self.action.setObjectName("action")
        self.actiondump = QtWidgets.QAction(MainWindow)
        self.actiondump.setObjectName("actiondump")

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label.setText(_translate("MainWindow", "??????????????????????????????"))
        self.label_2.setText(_translate("MainWindow", "??????????????????????????????"))
        self.label_3.setText(_translate("MainWindow", "??????????????????????????????"))
        self.label_4.setText(_translate("MainWindow", "??????ip"))
        self.label_5.setText(_translate("MainWindow", "????????????"))
        self.label_6.setText(_translate("MainWindow", "dump?????????????????????"))
        self.label_7.setText(_translate("MainWindow", "return??????????????????"))
        self.off_b.setText(_translate("MainWindow", "calculation"))
        self.label_8.setText(_translate("MainWindow", "stop_gadget?????????"))
        self.stop_b.setText(_translate("MainWindow", "calculation"))
        self.label_9.setText(_translate("MainWindow", "brop_gadget?????????"))
        self.brop_b.setText(_translate("MainWindow", "calculation"))
        self.label_10.setText(_translate("MainWindow", "plt???????????????"))
        self.plt_b.setText(_translate("MainWindow", "calculation"))
        self.label_11.setText(_translate("MainWindow", "puts???????????????"))
        self.puts_b.setText(_translate("MainWindow", "calculation"))
        self.dump_b.setText(_translate("MainWindow", "dump"))
        self.label_12.setText(_translate("MainWindow", "?????????????????????"))
        self.action.setText(_translate("MainWindow", "????????????"))
        self.actiondump.setText(_translate("MainWindow", "dump??????????????????"))
