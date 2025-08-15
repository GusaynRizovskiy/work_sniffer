# -*- coding: utf-8 -*-
import logging
import os
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtGui import QPalette, QBrush, QPixmap
from PyQt5.QtWidgets import QMessageBox, QFileDialog, QTableWidgetItem, QVBoxLayout, QHBoxLayout
from form_for_sniffer import Ui_tableWidget_metrics, TextEditLogger
from scapy.layers.inet import IP, UDP, TCP
from utils import address_in_network, get_working_ifaces
from datetime import datetime
from scapy.all import *
import sys
import csv
import platform
import ipaddress
import pyqtgraph as pg
import socket
import json
from PyQt5 import QtGui

# Класс, который будет наследоваться от QObject и выполнять основную работу программы
class Worker(QtCore.QObject):
    finished = QtCore.pyqtSignal()
    status_update = QtCore.pyqtSignal(str)
    packet_info_update = QtCore.pyqtSignal(str)
    all_metrics_update = QtCore.pyqtSignal(list)
    connection_status_update = QtCore.pyqtSignal(str)

    def __init__(self, mode, server_address=None, server_port=None):
        super().__init__()
        self.is_running = True
        self.data_all_intervals = []
        self.logger = logging.getLogger(__name__)
        self.mode = mode
        self.server_address = server_address
        self.server_port = server_port
        self.client_socket = None

    def run(self):
        self.is_running = True
        self.status_update.emit("Сниффинг запущен...")
        self.logger.info("Рабочий поток Worker запущен.")

        if self.mode == "online":
            self.connect_to_server()
            if not self.client_socket:
                self.is_running = False
                self.finished.emit()
                return

        while self.is_running:
            self.data_one_interval = []
            self.initialize_packet_counts()
            self.logger.debug("Счетчики пакетов инициализированы для нового интервала.")

            self.time_begin = datetime.now().strftime('%H:%M:%S')
            self.status_update.emit(
                f"Начало интервала агрегирования: {self.time_begin} (длительность {form.time_of_capture} с.)")
            self.logger.info(
                f"Начало интервала агрегирования: {self.time_begin} (длительность {form.time_of_capture} с.)")

            try:
                if not form.interface_of_capture:
                    self.status_update.emit("ОШИБКА: Интерфейс захвата не выбран. Сниффинг остановлен.")
                    self.logger.error("Интерфейс захвата не выбран. Завершение работы Worker.")
                    self.is_running = False
                    self.finished.emit()
                    return

                self.logger.debug(
                    f"Начало захвата пакетов: iface={form.interface_of_capture}, filter={form.network_cidr}, timeout={form.time_of_capture}")
                sniff(filter=f"net {form.network_cidr}", iface=form.interface_of_capture,
                      prn=self.packet_callback, store=False, timeout=form.time_of_capture)
                self.logger.debug("Захват пакетов завершен для текущего интервала.")
            except Exception as e:
                self.status_update.emit(
                    f"КРИТИЧЕСКАЯ ОШИБКА: Ошибка в процессе захвата пакетов: {e}. Сниффинг остановлен.")
                self.logger.critical(f"КРИТИЧЕСКАЯ ОШИБКА: Ошибка в процессе захвата пакетов: {e}", exc_info=True)
                self.is_running = False
                self.finished.emit()
                return

            self.time_end = datetime.now().strftime('%H:%M:%S')

            self.calculate_intensities()
            self.prepare_data_interval()

            all_metrics_data = [
                f"{self.time_begin}-{self.time_end}",
                self.count_capture_packets,
                self.count_input_packets,
                self.count_output_packets,
                self.count_tcp_segments,
                self.count_udp_segments,
                self.count_fragment_packets,
                self.count_loopback_packets,
                self.count_multicast_packets,
                self.count_intensivity_packets,
                self.count_input_intensivity_packets,
                self.count_output_intensivity_packets,
                self.count_fin_packets,
                self.count_sin_packets,
                self.count_input_fin_packets,
                self.count_input_sin_packets,
                self.count_output_fin_packets,
                self.count_output_sin_packets
            ]

            self.all_metrics_update.emit(all_metrics_data)

            if self.mode == "online":
                self.send_data_to_server(all_metrics_data)

            self.data_all_intervals.append(self.data_one_interval)
            self.status_update.emit("Интервал агрегирования завершен")
            self.logger.info("Интервал агрегирования завершен.")

        self.disconnect_from_server()
        self.finished.emit()
        self.logger.info("Рабочий поток Worker завершил работу.")

    def connect_to_server(self):
        """Устанавливает соединение с сервером."""
        self.connection_status_update.emit(f"Попытка подключения к серверу {self.server_address}:{self.server_port}...")
        self.logger.info(f"Попытка подключения к серверу: {self.server_address}:{self.server_port}")
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(5)
            self.client_socket.connect((self.server_address, self.server_port))
            self.connection_status_update.emit(f"Успешное подключение к серверу.")
            self.logger.info("Успешное подключение к серверу.")
        except socket.timeout:
            self.connection_status_update.emit(f"ОШИБКА: Не удалось подключиться к серверу: превышен тайм-аут.")
            self.logger.error("Ошибка подключения к серверу: превышен тайм-аут.")
            self.client_socket = None
        except socket.error as e:
            self.connection_status_update.emit(f"ОШИБКА: Ошибка сокета при подключении: {e}")
            self.logger.error(f"Ошибка сокета при подключении: {e}")
            self.client_socket = None
        except Exception as e:
            self.connection_status_update.emit(f"КРИТИЧЕСКАЯ ОШИБКА: Непредвиденная ошибка при подключении: {e}")
            self.logger.critical(f"Непредвиденная ошибка при подключении: {e}", exc_info=True)
            self.client_socket = None

    def disconnect_from_server(self):
        """Закрывает сокет-соединение."""
        if self.client_socket:
            self.client_socket.close()
            self.connection_status_update.emit("Соединение с сервером закрыто.")
            self.logger.info("Соединение с сервером закрыто.")

    def send_data_to_server(self, data):
        """Сериализует и отправляет данные на сервер."""
        if not self.client_socket:
            self.connection_status_update.emit("ОШИБКА: Соединение с сервером потеряно. Сниффинг остановлен.")
            self.is_running = False
            return

        try:
            json_data = json.dumps(data).encode('utf-8')
            self.client_socket.sendall(json_data)
            self.connection_status_update.emit(f"Данные для интервала {data[0]} успешно отправлены на сервер.")
            self.logger.info(f"Данные для интервала {data[0]} успешно отправлены.")
        except socket.error as e:
            self.connection_status_update.emit(
                f"ОШИБКА: Ошибка при отправке данных на сервер: {e}. Сниффинг остановлен.")
            self.logger.error(f"Ошибка при отправке данных на сервер: {e}", exc_info=True)
            self.is_running = False
        except Exception as e:
            self.connection_status_update.emit(
                f"КРИТИЧЕСКАЯ ОШИБКА: Непредвиденная ошибка при отправке: {e}. Сниффинг остановлен.")
            self.logger.critical(f"Непредвиденная ошибка при отправке данных: {e}", exc_info=True)
            self.is_running = False

    def initialize_packet_counts(self):
        """Инициализация всех переменных счетчиков пакетов для нового интервала."""
        self.count_loopback_packets = 0
        self.count_capture_packets = 0
        self.count_multicast_packets = 0
        self.count_udp_segments = 0
        self.count_tcp_segments = 0
        self.count_options_packets = 0
        self.count_fragment_packets = 0
        self.count_intensivity_packets = 0
        self.count_fin_packets = 0
        self.count_sin_packets = 0

        self.count_input_packets = 0
        self.count_input_udp_packets = 0
        self.count_input_tcp_packets = 0
        self.count_input_fin_packets = 0
        self.count_input_sin_packets = 0
        self.count_input_intensivity_packets = 0
        self.count_input_options_packets = 0
        self.count_input_fragment_packets = 0

        self.count_output_packets = 0
        self.count_output_udp_packets = 0
        self.count_output_tcp_packets = 0
        self.count_output_fin_packets = 0
        self.count_output_sin_packets = 0
        self.count_output_intensivity_packets = 0
        self.count_output_options_packets = 0
        self.count_output_fragment_packets = 0
        self.logger.debug("Счетчики пакетов сброшены.")

    def calculate_intensities(self):
        """Расчет интенсивности входящих и исходящих пакетов."""
        try:
            if form.time_of_capture > 0:
                self.count_input_intensivity_packets = (self.count_input_packets / form.time_of_capture)
                self.count_output_intensivity_packets = (self.count_output_packets / form.time_of_capture)
                self.count_intensivity_packets = (self.count_capture_packets / form.time_of_capture)
            else:
                self.count_input_intensivity_packets = 0
                self.count_output_intensivity_packets = 0
                self.count_intensivity_packets = 0
            self.logger.debug("Интенсивность пакетов рассчитана.")

        except Exception as e:
            self.status_update.emit(f"ОШИБКА: Произошла ошибка при расчете интенсивности пакетов: {e}")
            self.logger.error(f"Ошибка при расчете интенсивности пакетов: {e}", exc_info=True)
            self.count_input_intensivity_packets = 0
            self.count_output_intensivity_packets = 0
            self.count_intensivity_packets = 0

    def prepare_data_interval(self):
        """Подготовка данных для текущего интервала (для CSV)."""
        try:
            interval_data_formatting = [
                f"{self.time_begin}-{self.time_end}",
                self.count_capture_packets,
                self.count_loopback_packets,
                self.count_multicast_packets,
                self.count_udp_segments,
                self.count_tcp_segments,
                self.count_options_packets,
                self.count_fragment_packets,
                self.count_intensivity_packets,
                self.count_fin_packets,
                self.count_sin_packets,
                self.count_input_packets,
                self.count_input_udp_packets,
                self.count_input_tcp_packets,
                self.count_input_options_packets,
                self.count_input_fragment_packets,
                self.count_input_intensivity_packets,
                self.count_input_fin_packets,
                self.count_input_sin_packets,
                self.count_output_packets,
                self.count_output_udp_packets,
                self.count_output_tcp_packets,
                self.count_output_options_packets,
                self.count_output_fragment_packets,
                self.count_output_intensivity_packets,
                self.count_output_fin_packets,
                self.count_output_sin_packets,
            ]

            self.data_one_interval.clear()
            for data in interval_data_formatting:
                self.data_one_interval.append(data)
            self.logger.debug("Данные интервала подготовлены для CSV.")

        except Exception as e:
            self.status_update.emit(f"ОШИБКА: Произошла ошибка при подготовке данных интервала для CSV: {e}")
            self.logger.error(f"Ошибка при подготовке данных интервала для CSV: {e}", exc_info=True)

    def stop(self):
        """Устанавливает флаг для остановки выполнения рабочего потока."""
        self.is_running = False
        self.logger.info("Получен запрос на остановку рабочего потока Worker.")

    def packet_callback(self, packet):
        """Обработка захваченного пакета."""
        try:
            self.count_capture_packets += 1
            src_ip = "N/A"
            dst_ip = "N/A"

            if packet.haslayer("IP"):
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst
                self.packet_info_update.emit(f"Перехвачен пакет: {src_ip} -> {dst_ip}")

                if dst_ip == "255.255.255.255" or dst_ip.endswith(".255") or (
                        dst_ip.startswith("224.") or dst_ip.startswith("23")
                ):
                    self.count_multicast_packets += 1
                elif dst_ip == '127.0.0.1':
                    self.count_loopback_packets += 1
                elif form.network_cidr and not address_in_network(src_ip,
                                                                  form.network_cidr) and address_in_network(
                    dst_ip,
                    form.network_cidr):
                    self.count_input_packets += 1
                    self.parametrs_input_packets_count(packet)
                elif form.network_cidr and address_in_network(src_ip,
                                                              form.network_cidr) and not address_in_network(
                    dst_ip,
                    form.network_cidr):
                    self.count_output_packets += 1
                    self.parametrs_output_packets_count(packet)

                if packet.haslayer(IP) and packet[IP].options:
                    self.count_options_packets += 1
                if packet.haslayer(IP) and ((packet[IP].flags & 0x01) or (packet[IP].frag > 0)):
                    self.count_fragment_packets += 1

                if packet.haslayer('TCP'):
                    self.count_tcp_segments += 1
                    if packet[TCP].flags.has('F'):
                        self.count_fin_packets += 1
                    elif packet[TCP].flags.has('S'):
                        self.count_sin_packets += 1

                elif packet.haslayer('UDP'):
                    self.count_udp_segments += 1
            else:
                self.packet_info_update.emit(f"Перехвачен не-IP пакет: {packet.summary()}")

        except Exception as e:
            self.logger.warning(f"Ошибка при обработке пакета: {e}. Пакет пропущен.", exc_info=True)
            pass

    def parametrs_input_packets_count(self, packet):
        """Рассчет параметров для входящих пакетов."""
        try:
            if packet.haslayer('TCP'):
                self.count_input_tcp_packets += 1
                if packet[TCP].flags.has('F'):
                    self.count_input_fin_packets += 1
                elif packet[TCP].flags.has('S'):
                    self.count_input_sin_packets += 1
            elif packet.haslayer('UDP'):
                self.count_input_udp_packets += 1

            if packet.haslayer("IP") and ((packet[IP].flags & 0x01) or (packet[IP].frag > 0)):
                self.count_input_fragment_packets += 1

            if packet.haslayer("IP") and packet[IP].options:
                self.count_input_options_packets += 1

        except Exception as e:
            self.logger.warning(f"Ошибка при расчете параметров входящих пакетов: {e}", exc_info=True)
            pass

    def parametrs_output_packets_count(self, packet):
        """Рассчет параметров для исходящих пакетов."""
        try:
            if packet.haslayer('TCP'):
                self.count_output_tcp_packets += 1
                if packet[TCP].flags.has('F'):
                    self.count_output_fin_packets += 1
                elif packet[TCP].flags.has('S'):
                    self.count_output_sin_packets += 1
            elif packet.haslayer('UDP'):
                self.count_output_udp_packets += 1

            if packet.haslayer("IP") and ((packet[IP].flags & 0x01) or (packet[IP].frag > 0)):
                self.count_output_fragment_packets += 1

            if packet.haslayer("IP") and packet[IP].options:
                self.count_output_options_packets += 1

        except Exception as e:
            self.logger.warning(f"Ошибка при расчете параметров исходящих пакетов: {e}", exc_info=True)
            pass


# Основной класс, в котором происходит создание экземпляра формы и считывание данных пользователя.
class Form_main(QtWidgets.QMainWindow, Ui_tableWidget_metrics):
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.setupUi(self)

        self.graphWidget_intensity_layout = QVBoxLayout(self.graphWidget_intensity)
        self.plot_intensity = pg.PlotWidget()
        self.graphWidget_intensity_layout.addWidget(self.plot_intensity)

        self.graphWidget_traffic_direction_layout = QVBoxLayout(self.graphWidget_traffic_direction)
        self.plot_traffic_direction = pg.PlotWidget()
        self.graphWidget_traffic_direction_layout.addWidget(self.plot_traffic_direction)

        self.graphWidget_protocol_distribution_layout = QVBoxLayout(self.graphWidget_protocol_distribution)
        self.plot_protocol_distribution = pg.PlotWidget()
        self.graphWidget_protocol_distribution_layout.addWidget(self.plot_protocol_distribution)

        self.tableWidget_metric.setColumnCount(9)
        self.tableWidget_metric.setHorizontalHeaderLabels([
            'Время', 'Всего пакетов', 'Входящие (пак)', 'Исходящие (пак)',
            'TCP (сегм)', 'UDP (сегм)', 'Фрагменты (пак)', 'Multicast (пак)',
            'Интенсивность (пак/с)'
        ])
        self.tableWidget_metric.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        self.tableWidget_metric.horizontalHeader().setStretchLastSection(True)

        self.plot_intensity.setTitle("Интенсивность пакетов")
        self.plot_intensity.setLabel('left', 'Пакетов/с', units='пак/с')
        self.plot_intensity.setLabel('bottom', 'Интервал')
        self.plot_intensity.setBackground('w')
        self.curve_intensity = self.plot_intensity.plot(pen='b')
        self.intensity_data = []
        self.interval_indices_intensity = []

        self.plot_traffic_direction.setTitle("Входящий/Исходящий трафик")
        self.plot_traffic_direction.setLabel('left', 'Кол-во пакетов', units='пак')
        self.plot_traffic_direction.setLabel('bottom', 'Интервал')
        self.plot_traffic_direction.setBackground('w')
        self.curve_input = self.plot_traffic_direction.plot(pen='g', name='Входящие')
        self.curve_output = self.plot_traffic_direction.plot(pen='r', name='Исходящие')
        self.plot_traffic_direction.addLegend()
        self.input_packets_data = []
        self.output_packets_data = []
        self.interval_indices_traffic = []

        self.plot_protocol_distribution.setTitle("Соотношение TCP/UDP")
        self.plot_protocol_distribution.setLabel('left', 'Доля (%)')
        self.plot_protocol_distribution.setLabel('bottom', 'Протокол')
        self.plot_protocol_distribution.setBackground('w')
        self.bar_graph_item = pg.BarGraphItem(x=[1, 2], height=[0, 0], width=0.5, brushes=['blue', 'orange'])
        self.plot_protocol_distribution.addItem(self.bar_graph_item)
        self.plot_protocol_distribution.getAxis('bottom').setTicks([[(1, 'TCP'), (2, 'UDP')]])
        self.plot_protocol_distribution.setXRange(0.5, 2.5)
        self.plot_protocol_distribution.setYRange(0, 100)

        self.label_server_address = QtWidgets.QLabel(self.central_widget)
        self.label_server_address.setText("IP сервера:")
        self.label_server_address.setFont(QtGui.QFont("MS Shell Dlg 2", 14))
        self.lineEdit_server_address = QtWidgets.QLineEdit(self.central_widget)
        self.lineEdit_server_address.setPlaceholderText("127.0.0.1")
        self.lineEdit_server_address.setText("127.0.0.1")

        self.label_server_port = QtWidgets.QLabel(self.central_widget)
        self.label_server_port.setText("Порт:")
        self.label_server_port.setFont(QtGui.QFont("MS Shell Dlg 2", 14))
        self.spinBox_server_port = QtWidgets.QSpinBox(self.central_widget)
        self.spinBox_server_port.setRange(1024, 65535)
        self.spinBox_server_port.setValue(12345)

        self.verticalLayout.addWidget(self.label_server_address)
        self.verticalLayout_2.addWidget(self.lineEdit_server_address)
        self.verticalLayout.addWidget(self.label_server_port)
        self.verticalLayout_2.addWidget(self.spinBox_server_port)

        self.label_server_address.hide()
        self.lineEdit_server_address.hide()
        self.label_server_port.hide()
        self.spinBox_server_port.hide()

        self.thread = QtCore.QThread()
        self.worker = None

        self.pushBatton_start_capture.clicked.connect(self.show_mode_warning)
        self.pushBatton_start_online.clicked.connect(self.start_online_mode)
        self.pushBatton_start_offline.clicked.connect(self.start_offline_mode)
        self.pushButton_stop_capture.clicked.connect(self.stop_sniffing)
        self.pushBatton_finish_work.clicked.connect(self.close_program)
        self.pushButton_save_in_file.clicked.connect(self.save_file_as_csv)

        self.interface_display_to_internal_map = {}
        self.pushButton_save_in_file.setEnabled(False)

        self.comboBox_interface_of_capture = QtWidgets.QComboBox(self.central_widget)
        self.comboBox_interface_of_capture.setObjectName("comboBox_interface_of_capture")
        self.verticalLayout_2.insertWidget(1, self.comboBox_interface_of_capture)
        self.populate_interfaces_combo_box(self.comboBox_interface_of_capture)

        self.logger.info("Приложение Form_main инициализировано.")

    def show_mode_warning(self):
        """Отображает предупреждение о необходимости выбора режима."""
        QMessageBox.information(self, "Выбор режима",
                                "Пожалуйста, выберите режим работы: 'Online' для отправки данных на сервер или 'Offline' для локального анализа.")
        self.logger.info("Пользователю показано предупреждение о необходимости выбора режима.")

    def start_offline_mode(self):
        """Запускает сниффинг в локальном режиме."""
        self.logger.info("Пользователь выбрал Offline-режим.")
        self.label_name_capture_display.setText("Оффлайн-режим")
        self.label_server_address.hide()
        self.lineEdit_server_address.hide()
        self.label_server_port.hide()
        self.spinBox_server_port.hide()
        self.check_input_data(mode="offline")

    def start_online_mode(self):
        """Запускает сниффинг в режиме отправки данных на сервер."""
        self.logger.info("Пользователь выбрал Online-режим.")
        self.label_name_capture_display.setText("Онлайн-режим")
        self.label_server_address.show()
        self.lineEdit_server_address.show()
        self.label_server_port.show()
        self.spinBox_server_port.show()
        self.check_input_data(mode="online")

    def check_input_data(self, mode):
        self.logger.info("Начата проверка входных данных.")
        try:
            selected_display_name = self.comboBox_interface_of_capture.currentText().strip()
            self.network_cidr = self.lineEdit_network_capture.text().strip()
            self.time_of_capture = self.spinBox_time_of_capture.value()

            if not selected_display_name:
                QMessageBox.warning(self, "Предупреждение", "Необходимо выбрать сетевой интерфейс.")
                self.logger.warning("Попытка начать сниффинг без выбора интерфейса.")
                return
            elif not self.network_cidr or self.time_of_capture == self.spinBox_time_of_capture.minimum():
                QMessageBox.warning(self, "Предупреждение",
                                    "Необходимо ввести все данные для работы (сеть и время захвата).")
                self.logger.warning("Попытка начать сниффинг без полных входных данных.")
                return

            if '/' not in self.network_cidr:
                error_message = ("Некорректный формат адреса сети.\n"
                                 "Пожалуйста, введите адрес сети вместе с маской (например, 192.168.1.0/24).")
                QMessageBox.warning(self, "Ошибка ввода", error_message)
                self.logger.error(f"Некорректный формат сети введен: {self.network_cidr}. Отсутствует маска.")
                return

            try:
                ipaddress.ip_network(self.network_cidr, strict=False)
                self.logger.info(
                    f"Входные данные успешно проверены: Интерфейс='{selected_display_name}', Сеть='{self.network_cidr}', Время='{self.time_of_capture}'")
            except ValueError:
                QMessageBox.warning(self, "Ошибка ввода",
                                    "Некорректный формат сети. Используйте CIDR-нотацию (например, 192.168.1.0/24).")
                self.logger.error(f"Некорректный формат сети введен: {self.network_cidr}", exc_info=True)
                return

            self.start_sniffing(mode)

        except ValueError as ve:
            QMessageBox.warning(self, "Ошибка ввода", str(ve))
            self.logger.error(f"Ошибка ввода данных: {ve}", exc_info=True)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Произошла непредвиденная ошибка при проверке данных: {e}")
            self.logger.critical(f"Непредвиденная ошибка при проверке входных данных:{e}", exc_info=True)

    def start_sniffing(self, mode):
        self.pushButton_stop_capture.setEnabled(True)
        self.logger.info("Попытка начать сниффинг.")
        try:
            selected_display_name = self.comboBox_interface_of_capture.currentText().strip()
            self.interface_of_capture = self.interface_display_to_internal_map.get(
                selected_display_name, selected_display_name
            )

            if not self.time_of_capture > 0:
                raise ValueError("Время захвата должно быть больше нуля.")
            if not self.interface_of_capture:
                raise ValueError("Необходимо выбрать интерфейс для захвата.")
            if not self.network_cidr:
                raise ValueError("Необходимо указать сеть для захвата.")
            try:
                ipaddress.ip_network(self.network_cidr, strict=False)
            except ValueError:
                raise ValueError("Некорректный формат сети. Используйте CIDR-нотацию (например, 192.168.1.0/24).")

            self.update_status_text_zone("Начало инициализации сниффера...")
            self.logger.info("Инициализация сниффера...")

            self.pushBatton_finish_work.setEnabled(False)
            self.pushBatton_start_capture.setEnabled(False)
            self.plainTextEdit.clear()
            self.tableWidget_metric.setRowCount(0)

            self.intensity_data.clear()
            self.interval_indices_intensity.clear()
            self.curve_intensity.setData([], [])

            self.input_packets_data.clear()
            self.output_packets_data.clear()
            self.interval_indices_traffic.clear()
            self.curve_input.setData([], [])
            self.curve_output.setData([], [])

            self.bar_graph_item.setOpts(height=[0, 0])
            self.plot_protocol_distribution.setYRange(0, 100)

            if self.thread.isRunning():
                QMessageBox.information(self, "Информация",
                                        "Сниффер уже запущен. Сначала остановите его, чтобы начать новый захват.")
                self.update_status_text_zone("ПРЕДУПРЕЖДЕНИЕ: Сниффер уже запущен.")
                self.logger.warning("Попытка повторного запуска уже работающего сниффера.")
                self.pushBatton_start_capture.setEnabled(True)
                self.pushButton_stop_capture.setEnabled(True)
                return

            if self.worker:
                self.worker.deleteLater()

            if mode == "online":
                server_address = self.lineEdit_server_address.text().strip()
                server_port = self.spinBox_server_port.value()
                self.worker = Worker(mode="online", server_address=server_address, server_port=server_port)
            else:
                self.worker = Worker(mode="offline")

            self.worker.moveToThread(self.thread)
            self.thread.started.connect(self.worker.run)
            self.worker.finished.connect(self.on_finished)
            self.worker.status_update.connect(self.update_status_text_zone)
            self.worker.packet_info_update.connect(self.update_status_text_zone)
            self.worker.all_metrics_update.connect(self.update_metrics_table)
            self.worker.all_metrics_update.connect(self.update_intensity_graph)
            self.worker.all_metrics_update.connect(self.update_traffic_direction_graph)
            self.worker.all_metrics_update.connect(self.update_protocol_distribution_graph)
            self.worker.connection_status_update.connect(self.update_status_text_zone)

            self.logger.info("UI очищен, кнопки заблокированы.")
            self.worker.data_all_intervals.clear()
            self.logger.debug("Данные для записи сброшены.")

            self.thread.start()
            self.logger.info("Рабочий поток запущен.")

        except Exception as e:
            error_message = f"Не удалось начать сниффинг: {e}"
            if "No such device" in str(e) or "interface" in str(e).lower():
                error_message = (f"Выбранный сетевой интерфейс не найден или недоступен.\n"
                                 f"Возможно, он был отключен, или указано неверное имя интерфейса.\n"
                                 f"Попробуйте выбрать другой интерфейс или перезапустить программу.")
            elif "Permission denied" in str(e) or "You don't have enough privileges" in str(e):
                error_message = (f"Недостаточно прав для запуска сниффинга.\n"
                                 f"Пожалуйста, запустите программу от имени администратора (для Windows) "
                                 f"или с root-правами (для Linux/macOS).")
            elif "WinPcap is not installed" in str(e) or "Npcap is not installed" in str(e) or "libpcap" in str(e):
                error_message = (f"Не удалось найти библиотеку захвата пакетов (WinPcap/Npcap/libpcap).\n"
                                 f"Убедитесь, что она установлена и настроена корректно.")
            else:
                error_message = (f"Произошла непредвиденная ошибка при попытке начать сниффинг: {e}\n"
                                 f"Пожалуйста, проверьте конфигурацию Scapy и права доступа.")

            QMessageBox.critical(self, "Ошибка запуска сниффера", error_message)
            self.update_status_text_zone(f"ОШИБКА ЗАПУСКА: {error_message}")
            self.logger.critical(f"Ошибка запуска сниффера: {error_message}", exc_info=True)
            self.pushBatton_start_capture.setEnabled(True)
            self.pushButton_stop_capture.setEnabled(False)
            self.pushBatton_finish_work.setEnabled(True)

    def stop_sniffing(self):
        """Останавливает фоновый поток сниффинга."""
        self.logger.info("Пользователь запросил остановку сниффинга.")
        try:
            if self.thread.isRunning():
                if self.worker:
                    self.worker.stop()
                self.thread.quit()
                self.thread.wait()
                self.pushButton_stop_capture.setEnabled(False)
                QMessageBox.information(self, "Сниффер", "Сниффинг остановлен.")
                self.update_status_text_zone("Сниффинг остановлен пользователем.")
                self.logger.info("Сниффинг успешно остановлен.")
                self.pushBatton_start_capture.setEnabled(True)
                self.pushButton_save_in_file.setEnabled(True)
                self.pushBatton_finish_work.setEnabled(True)
            else:
                QMessageBox.information(self, "Сниффер", "Сниффинг не был запущен.")
                self.update_status_text_zone("ПРЕДУПРЕЖДЕНИЕ: Попытка остановить не запущенный сниффер.")
                self.logger.warning("Попытка остановить сниффер, который не запущен.")
        except Exception as e:
            self.update_status_text_zone(f"ОШИБКА: Произошла ошибка при остановке сниффера: {e}")
            self.logger.critical(f"Ошибка при остановке сниффера: {e}", exc_info=True)
            QMessageBox.critical(self, "Ошибка", f"Произошла ошибка при остановке сниффера: {e}")

    def on_finished(self):
        """Функция выполняется, когда рабочий поток Worker завершает свою работу."""
        self.update_status_text_zone("Сниффер завершил свою работу.")
        self.logger.info("Рабочий поток Worker завершил работу (сигнал finished).")
        self.pushButton_save_in_file.setEnabled(True)
        self.pushBatton_finish_work.setEnabled(True)
        self.pushBatton_start_capture.setEnabled(True)

    def save_file_as_csv(self):
        """Сохранение данных в CSV файл."""
        self.logger.info("Пользователь запросил сохранение данных в CSV.")
        try:
            if not self.worker or not self.worker.data_all_intervals:
                raise ValueError("Нет данных для сохранения.")

            options = QFileDialog.Options()
            options |= QFileDialog.DontUseNativeDialog

            file_name, _ = QFileDialog.getSaveFileName(self,
                                                       "Сохранить данные сниффинга",
                                                       "sniffing_data.csv",
                                                       "CSV Files (*.csv);;All Files (*)",
                                                       options=options)

            if not file_name:
                QMessageBox.information(self, "Отмена", "Сохранение файла отменено.")
                self.update_status_text_zone("Сохранение файла отменено.")
                self.logger.info("Сохранение файла отменено пользователем.")
                return

            if not file_name.endswith('.csv'):
                file_name += '.csv'

            self.update_status_text_zone(f"Начато сохранение данных в файл: {file_name}")
            self.logger.info(f"Сохранение данных в файл: {file_name}")
            with open(file_name, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow([
                    'Время захвата пакетов',
                    'Общее число захваченных пакетов', 'Число пакетов localhost', 'Число пакетов broadcast/multicast',
                    'Число UDP сегментов', 'Число TCP сегментов', 'Число пакетов с опциями',
                    'Число фрагментированных пакетов', 'Общая интенсивность пакетов',
                    "Количество пакетов типа FIN", 'Количество пакетов типа SYN',
                    'Число пакетов, входящих в сеть', "Число UDP сегментов входящих в сеть",
                    "Число TCP сегментов, входящих в сеть", "Число пакетов с опциями, входящих в сеть",
                    "Число фрагментированных пакетов, входящих в сеть", "Интенсивность пакетов, входящих в сеть",
                    "Количество пакетов типа FIN, входящих в сеть", "Количество пакетов типа SYN, входящих в сеть",
                    'Число пакетов, исходящих из сети', "Число UDP сегментов, исходящих из сети",
                    "Число TCP сегментов, исходящих из сети", "Число пакетов с опциями, исходящих из сети",
                    "Число фрагментированных пакетов, исходящих из сети", "Интенсивность пакетов, исходящих из сети",
                    "Количество пакетов типа FIN, исходящих из сети", "Количество пакетов типа SYN, исходящих из сети",
                ])
                for i in range(len(self.worker.data_all_intervals)):
                    writer.writerow(self.worker.data_all_intervals[i])
            self.logger.info(f"Данные успешно записаны в файл: {file_name}")

            QMessageBox.information(self, "Успех", f"Данные успешно сохранены в файл: {file_name}")
            self.update_status_text_zone(f"Данные успешно сохранены в: {file_name}")

        except ValueError as ve:
            self.update_status_text_zone(f"ОШИБКА: Ошибка при сохранении файла (нет данных): {ve}")
            self.logger.warning(f"Ошибка при сохранении файла: {ve} (нет данных).", exc_info=True)
            QMessageBox.warning(self, "Ошибка", str(ve))
        except Exception as e:
            self.update_status_text_zone(f"КРИТИЧЕСКАЯ ОШИБКА: Произошла при сохранении файла: {e}")
            self.logger.critical(f"Непредвиденная ошибка при сохранении данных: {e}", exc_info=True)
            QMessageBox.critical(self, "Ошибка", f"Произошла ошибка при сохранении данных: {e}")

    def close_program(self):
        """Функция отвечающая за закрытие программы."""
        self.logger.info("Запрошено закрытие программы.")
        try:
            if self.thread.isRunning():
                if self.worker:
                    self.worker.stop()
                self.thread.quit()
                self.thread.wait()
                self.logger.info("Рабочий поток успешно завершен перед закрытием.")

            self.close()
            self.logger.info("Приложение закрыто.")

        except Exception as e:
            self.logger.error(f"Ошибка при закрытии программы: {e}", exc_info=True)
            pass

    def update_status_text_zone(self, message):
        """Добавляет сообщение в текстовую область с временной меткой и прокручивает его."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        formatted_message = f"[{timestamp}] {message}"
        self.plainTextEdit.appendPlainText(formatted_message)
        self.plainTextEdit.verticalScrollBar().setValue(self.plainTextEdit.verticalScrollBar().maximum())
        self.logger.debug(f"Сообщение отправлено в UI: {message}")

    def update_metrics_table(self, all_metrics_data):
        """
        Обновляет таблицу агрегированных метрик.
        :param all_metrics_data: Полный список метрик от Worker.
        """
        try:
            metrics_for_table = [
                all_metrics_data[0],
                str(all_metrics_data[1]),
                str(all_metrics_data[2]),
                str(all_metrics_data[3]),
                str(all_metrics_data[4]),
                str(all_metrics_data[5]),
                str(all_metrics_data[6]),
                str(all_metrics_data[8]),
                f"{all_metrics_data[9]:.2f}"
            ]
            row_position = self.tableWidget_metric.rowCount()
            self.tableWidget_metric.insertRow(row_position)
            for col, data in enumerate(metrics_for_table):
                item = QTableWidgetItem(str(data))
                self.tableWidget_metric.setItem(row_position, col, item)
            self.tableWidget_metric.scrollToBottom()
            self.logger.debug(f"Метрики добавлены в таблицу: {metrics_for_table}")
        except Exception as e:
            self.logger.error(f"Ошибка при обновлении таблицы метрик: {e}", exc_info=True)
            self.update_status_text_zone(f"ОШИБКА: Не удалось обновить таблицу метрик: {e}")

    def update_intensity_graph(self, all_metrics_data):
        """
        Обновляет график интенсивности.
        :param all_metrics_data: Полный список метрик от Worker.
        """
        try:
            intensity_value = float(all_metrics_data[9])
            self.intensity_data.append(intensity_value)
            self.interval_indices_intensity.append(len(self.interval_indices_intensity))
            max_points = 50
            if len(self.intensity_data) > max_points:
                self.intensity_data = self.intensity_data[-max_points:]
                self.interval_indices_intensity = self.interval_indices_intensity[-max_points:]
                self.interval_indices_intensity = list(range(len(self.intensity_data)))
            self.curve_intensity.setData(self.interval_indices_intensity, self.intensity_data)
            self.logger.debug(f"График интенсивности обновлен: {intensity_value} пак/с")
        except Exception as e:
            self.logger.error(f"Ошибка при обновлении графика интенсивности: {e}", exc_info=True)
            self.update_status_text_zone(f"ОШИБКА: Не удалось обновить график интенсивности: {e}")

    def update_traffic_direction_graph(self, all_metrics_data):
        """
        Обновляет график входящего/исходящего трафика.
        :param all_metrics_data: Полный список метрик от Worker.
        """
        try:
            input_packets = float(all_metrics_data[2])
            output_packets = float(all_metrics_data[3])
            self.input_packets_data.append(input_packets)
            self.output_packets_data.append(output_packets)
            self.interval_indices_traffic.append(len(self.interval_indices_traffic))
            max_points = 50
            if len(self.input_packets_data) > max_points:
                self.input_packets_data = self.input_packets_data[-max_points:]
                self.output_packets_data = self.output_packets_data[-max_points:]
                self.interval_indices_traffic = self.interval_indices_traffic[-max_points:]
                self.interval_indices_traffic = list(range(len(self.input_packets_data)))
            self.curve_input.setData(self.interval_indices_traffic, self.input_packets_data)
            self.curve_output.setData(self.interval_indices_traffic, self.output_packets_data)
            self.logger.debug(f"График входящего/исходящего трафика обновлен: Вх={input_packets}, Исх={output_packets}")
        except Exception as e:
            self.logger.error(f"Ошибка при обновлении графика входящего/исходящего трафика: {e}", exc_info=True)
            self.update_status_text_zone(f"ОШИБКА: Не удалось обновить график входящего/исходящего трафика: {e}")

    def update_protocol_distribution_graph(self, all_metrics_data):
        """
        Обновляет гистограмму соотношения TCP/UDP.
        :param all_metrics_data: Полный список метрик от Worker.
        """
        try:
            tcp_segments = float(all_metrics_data[4])
            udp_segments = float(all_metrics_data[5])
            total_segments = tcp_segments + udp_segments
            if total_segments > 0:
                tcp_percent = (tcp_segments / total_segments) * 100
                udp_percent = (udp_segments / total_segments) * 100
            else:
                tcp_percent = 0
                udp_percent = 0
            self.bar_graph_item.setOpts(height=[tcp_percent, udp_percent])
            current_y_range = self.plot_protocol_distribution.getViewBox().viewRange()[1][1]
            max_val = max(tcp_percent, udp_percent, 10)
            if max_val * 1.1 > current_y_range:
                self.plot_protocol_distribution.setYRange(0, max_val * 1.1)
            self.logger.debug(f"График соотношения TCP/UDP обновлен: TCP={tcp_percent:.2f}%, UDP={udp_percent:.2f}%")
        except Exception as e:
            self.logger.error(f"Ошибка при обновлении графика соотношения TCP/UDP: {e}", exc_info=True)
            self.update_status_text_zone(f"ОШИБКА: Не удалось обновить график соотношения TCP/UDP: {e}")

    def populate_interfaces_combo_box(self, combo_box_widget):
        self.logger.info("Попытка заполнить список сетевых интерфейсов.")
        try:
            combo_box_widget.clear()
            self.interface_display_to_internal_map.clear()
            interfaces = get_working_ifaces()
            if not interfaces:
                QMessageBox.warning(self, "Предупреждение", "Не найдено сетевых интерфейсов. "
                                                            "Убедитесь, что WinPcap/Npcap установлен(а) (для Windows) "
                                                            "и программа запущена с правами администратора/root.")
                self.logger.warning(
                    "Не найдено сетевых интерфейсов. Возможно, нет прав или не установлен Npcap/WinPcap.")
                return
            for iface in interfaces:
                display_name = iface.description if iface.description else iface.name
                internal_name = iface.name
                self.logger.debug(f"Добавляем интерфейс в ComboBox: '{display_name}' (Внутреннее: '{internal_name}')")
                combo_box_widget.addItem(display_name)
                self.interface_display_to_internal_map[display_name] = internal_name
                self.logger.info(f"Найден интерфейс: {display_name} (Внутреннее имя: {internal_name})")
            self.logger.info(f"ComboBox содержит {combo_box_widget.count()} элементов после заполнения.")
        except Exception as e:
            self.logger.critical(f"Не удалось получить список сетевых интерфейсов: {e}", exc_info=True)
            QMessageBox.critical(self, "Ошибка загрузки интерфейсов",
                                 f"Не удалось получить список сетевых интерфейсов: {e}\n"
                                 "Пожалуйста, убедитесь, что WinPcap/Npcap установлен(а) (для Windows) и у программы есть необходимые права (например, запуск от имени администратора/root).")


if __name__ == '__main__':
    log_directory = "logs"
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)
    log_file_path = os.path.join(log_directory, "app.log")
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(name)s - %(funcName)s - Line:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler(log_file_path, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    app = QtWidgets.QApplication(sys.argv)
    form = Form_main()
    background_image_path = "fon/pucture_fon2.jpg"
    try:
        if os.path.exists(background_image_path):
            palette = QPalette()
            palette.setBrush(QPalette.Window, QBrush(QPixmap(background_image_path)))
            form.setPalette(palette)
            logging.info(f"Фоновое изображение успешно загружено: {background_image_path}")
        else:
            logging.warning(
                f"Фоновое изображение не найдено по пути: {background_image_path}. Фон не будет установлен.")
    except Exception as e:
        logging.error(f"Ошибка при загрузке фонового изображения '{background_image_path}': {e}", exc_info=True)
        QMessageBox.critical(form, "Ошибка загрузки фона", f"Не удалось загрузить фоновое изображение: {e}")
    form.showMaximized()
    sys.exit(app.exec_())