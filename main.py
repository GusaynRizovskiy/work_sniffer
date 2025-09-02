# -*- coding: utf-8 -*-
"""
Этот модуль представляет собой приложение для анализа сетевого трафика (пакетный сниффер),
разработанное с использованием PyQT5 для графического интерфейса и Scapy для
захвата и обработки пакетов.

Основные функции программы:
1. Захват пакетов с выбранного сетевого интерфейса.
2. Фильтрация пакетов по указанному CIDR-адресу сети.
3. Агрегирование метрик трафика (общее количество пакетов, TCP/UDP, входящий/исходящий)
   за заданные временные интервалы.
4. Отображение агрегированных метрик в таблице и в виде графиков в реальном времени.
5. Работа в двух режимах:
   - 'Offline': Локальный анализ и сохранение данных.
   - 'Online': Отправка агрегированных метрик на удаленный сервер по сокету.
6. Сохранение собранных данных в CSV-файл.
7. Логирование событий и ошибок для отладки.

Программа использует многопоточность для выполнения длительного процесса захвата пакетов
в фоновом режиме, чтобы не блокировать основной поток пользовательского интерфейса.
"""

import logging
import os
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtGui import QPalette, QBrush, QPixmap
from PyQt5.QtWidgets import QMessageBox, QFileDialog, QTableWidgetItem, QVBoxLayout, QHBoxLayout
from form_for_sniffer import Ui_tableWidget_metrics, TextEditLogger
from scapy.layers.inet import IP, UDP, TCP
from utils import address_in_network, get_working_ifaces
from datetime import datetime
from scapy.all import *
import sys
import csv
import ipaddress
import pyqtgraph as pg
import socket
import json


# Класс, который будет наследоваться от QObject и выполнять основную работу программы
class Worker(QtCore.QObject):
    """
    Класс Worker выполняет основную работу по захвату и анализу сетевых пакетов.
    Он запускается в отдельном потоке (QThread) для предотвращения зависания
    главного пользовательского интерфейса.
    """
    # Определяем сигналы, которые Worker может отправлять в основной поток UI
    finished = QtCore.pyqtSignal()
    status_update = QtCore.pyqtSignal(str)
    packet_info_update = QtCore.pyqtSignal(str)
    all_metrics_update = QtCore.pyqtSignal(list)
    connection_status_update = QtCore.pyqtSignal(str)

    def __init__(self, mode, server_address=None, server_port=None):
        """
        Инициализирует Worker.

        :param mode: Режим работы ("online" или "offline").
        :param server_address: IP-адрес сервера (только для онлайн-режима).
        :param server_port: Порт сервера (только для онлайн-режима).
        """
        super().__init__()
        self.is_running = True  # Флаг для управления циклом сниффинга
        self.data_all_intervals = []  # Список для хранения данных за все интервалы
        self.logger = logging.getLogger(__name__)
        self.mode = mode
        self.server_address = server_address
        self.server_port = server_port
        self.client_socket = None
        self.packet_counts = {}

    def run(self):
        """
        Основной цикл работы потока Worker. Запускает сниффинг в цикле,
        агрегируя данные за каждый интервал.
        """
        self.is_running = True
        self.status_update.emit("Сниффинг запущен...")
        self.logger.info("Рабочий поток Worker запущен.")

        if self.mode == "online":
            self.connect_to_server()
            if not self.client_socket:
                # Если подключение не удалось, завершаем работу
                self.is_running = False
                self.finished.emit()
                return

        while self.is_running:
            # Сбрасываем данные и счетчики для нового интервала
            self.data_one_interval = []
            self.initialize_packet_counts()
            self.logger.debug("Счетчики пакетов инициализированы для нового интервала.")

            # Сохраняем время начала интервала
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
                # Вызываем scapy.sniff для захвата пакетов
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

            # Подготавливаем данные для отправки в основной UI поток
            all_metrics_data = [
                f"{self.time_begin}-{self.time_end}",
                self.packet_counts['total']['packets'],
                self.packet_counts['total']['loopback'],
                self.packet_counts['total']['multicast'],
                self.packet_counts['total']['udp'],
                self.packet_counts['total']['tcp'],
                self.packet_counts['total']['options'],
                self.packet_counts['total']['fragment'],
                self.count_intensivity_packets,
                self.packet_counts['total']['fin'],
                self.packet_counts['total']['sin'],
                self.packet_counts['input']['packets'],
                self.packet_counts['input']['udp'],
                self.packet_counts['input']['tcp'],
                self.packet_counts['input']['options'],
                self.packet_counts['input']['fragment'],
                self.count_input_intensivity_packets,
                self.packet_counts['input']['fin'],
                self.packet_counts['input']['sin'],
                self.packet_counts['output']['packets'],
                self.packet_counts['output']['udp'],
                self.packet_counts['output']['tcp'],
                self.packet_counts['output']['options'],
                self.packet_counts['output']['fragment'],
                self.count_output_intensivity_packets,
                self.packet_counts['output']['fin'],
                self.packet_counts['output']['sin']
            ]

            # Отправляем сигнал с обновленными метриками
            self.all_metrics_update.emit(all_metrics_data)

            if self.mode == "online":
                self.send_data_to_server(all_metrics_data)

            # Добавляем данные текущего интервала в общий список
            self.data_all_intervals.append(self.data_one_interval)
            self.status_update.emit("Интервал агрегирования завершен")
            self.logger.info("Интервал агрегирования завершен.")

        self.disconnect_from_server()
        self.finished.emit()  # Отправляем сигнал о завершении работы
        self.logger.info("Рабочий поток Worker завершил работу.")

    def connect_to_server(self):
        """Устанавливает соединение с сервером."""
        self.connection_status_update.emit(f"Попытка подключения к серверу {self.server_address}:{self.server_port}...")
        self.logger.info(f"Попытка подключения к серверу: {self.server_address}:{self.server_port}")
        try:
            # Создаем сокет и устанавливаем тайм-аут
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(5)
            self.client_socket.connect((self.server_address, self.server_port))
            self.connection_status_update.emit("Успешное подключение к серверу.")
            self.logger.info("Успешное подключение к серверу.")
        except socket.timeout:
            # Обрабатываем ошибку тайм-аута
            self.connection_status_update.emit("ОШИБКА: Не удалось подключиться к серверу: превышен тайм-аут.")
            self.logger.error("Ошибка подключения к серверу: превышен тайм-аут.")
            self.client_socket = None
        except socket.error as e:
            # Обрабатываем другие ошибки сокета
            self.connection_status_update.emit(f"ОШИБКА: Ошибка сокета при подключении: {e}")
            self.logger.error(f"Ошибка сокета при подключении: {e}")
            self.client_socket = None
        except Exception as e:
            # Обрабатываем любые другие непредвиденные ошибки
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
            # Сериализуем данные в JSON и кодируем в байты
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
        self.packet_counts = {
            'total': {'packets': 0, 'loopback': 0, 'multicast': 0, 'udp': 0, 'tcp': 0, 'options': 0, 'fragment': 0,
                      'fin': 0, 'sin': 0, 'intensivity': 0},
            'input': {'packets': 0, 'udp': 0, 'tcp': 0, 'options': 0, 'fragment': 0, 'fin': 0, 'sin': 0, 'intensivity': 0},
            'output': {'packets': 0, 'udp': 0, 'tcp': 0, 'options': 0, 'fragment': 0, 'fin': 0, 'sin': 0, 'intensivity': 0}
        }
        self.logger.debug("Счетчики пакетов сброшены.")

    def calculate_intensities(self):
        """Расчет интенсивности входящих и исходящих пакетов."""
        try:
            # Вычисляем интенсивность пакетов, если время захвата больше 0
            if form.time_of_capture > 0:
                self.count_input_intensivity_packets = (self.packet_counts['input']['packets'] / form.time_of_capture)
                self.count_output_intensivity_packets = (self.packet_counts['output']['packets'] / form.time_of_capture)
                self.count_intensivity_packets = (self.packet_counts['total']['packets'] / form.time_of_capture)
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
            # Формируем список данных для записи в файл
            interval_data_formatting = [
                f"{self.time_begin}-{self.time_end}",
                self.packet_counts['total']['packets'],
                self.packet_counts['total']['loopback'],
                self.packet_counts['total']['multicast'],
                self.packet_counts['total']['udp'],
                self.packet_counts['total']['tcp'],
                self.packet_counts['total']['options'],
                self.packet_counts['total']['fragment'],
                self.count_intensivity_packets,
                self.packet_counts['total']['fin'],
                self.packet_counts['total']['sin'],
                self.packet_counts['input']['packets'],
                self.packet_counts['input']['udp'],
                self.packet_counts['input']['tcp'],
                self.packet_counts['input']['options'],
                self.packet_counts['input']['fragment'],
                self.count_input_intensivity_packets,
                self.packet_counts['input']['fin'],
                self.packet_counts['input']['sin'],
                self.packet_counts['output']['packets'],
                self.packet_counts['output']['udp'],
                self.packet_counts['output']['tcp'],
                self.packet_counts['output']['options'],
                self.packet_counts['output']['fragment'],
                self.count_output_intensivity_packets,
                self.packet_counts['output']['fin'],
                self.packet_counts['output']['sin'],
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
            # Обновляем общие счетчики
            self.update_packet_counts(packet, 'total')

            src_ip = "N/A"
            dst_ip = "N/A"

            if packet.haslayer("IP"):
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst
                self.packet_info_update.emit(f"Перехвачен пакет: {src_ip} -> {dst_ip}")

                # Определяем тип пакета (multicast, loopback)
                if dst_ip == "255.255.255.255" or dst_ip.endswith(".255") or (
                        dst_ip.startswith("224.") or dst_ip.startswith("23")
                ):
                    self.packet_counts['total']['multicast'] += 1
                elif dst_ip == '127.0.0.1':
                    self.packet_counts['total']['loopback'] += 1
                # Определяем направление (входящий или исходящий)
                elif form.network_cidr and not address_in_network(src_ip, form.network_cidr) and address_in_network(
                        dst_ip, form.network_cidr):
                    self.update_packet_counts(packet, 'input')
                elif form.network_cidr and address_in_network(src_ip, form.network_cidr) and not address_in_network(
                        dst_ip, form.network_cidr):
                    self.update_packet_counts(packet, 'output')
            else:
                self.packet_info_update.emit(f"Перехвачен не-IP пакет: {packet.summary()}")

        except Exception as e:
            self.logger.warning(f"Ошибка при обработке пакета: {e}. Пакет пропущен.", exc_info=True)
            pass

    def update_packet_counts(self, packet, direction):
        """
        Обновляет счетчики пакетов для заданного направления.
        :param packet: Перехваченный пакет.
        :param direction: 'total', 'input' или 'output'.
        """
        if direction not in self.packet_counts:
            self.logger.warning(f"Неизвестное направление для подсчета: {direction}")
            return

        counts = self.packet_counts[direction]
        counts['packets'] += 1

        if packet.haslayer('IP'):
            # Проверяем наличие опций в IP-заголовке
            if 'options' in packet[IP].fields and packet[IP].options:
                counts['options'] += 1
            # Проверяем наличие фрагментации
            if (packet[IP].flags & 0x01) or (packet[IP].frag > 0):
                counts['fragment'] += 1

            # Проверяем тип протокола (TCP или UDP)
            if packet.haslayer('TCP'):
                counts['tcp'] += 1
                if 'F' in str(packet[TCP].flags):
                    counts['fin'] += 1
                elif 'S' in str(packet[TCP].flags):
                    counts['sin'] += 1
            elif packet.haslayer('UDP'):
                counts['udp'] += 1

        self.logger.debug(f"Счетчики для направления '{direction}' обновлены.")


# Основной класс, в котором происходит создание экземпляра формы и считывание данных пользователя.
class Form_main(QtWidgets.QMainWindow, Ui_tableWidget_metrics):
    """
    Главное окно приложения, управляющее пользовательским интерфейсом,
    взаимодействием с Worker-потоком и визуализацией данных.
    """
    def __init__(self):
        """
        Конструктор класса Form_main. Инициализирует UI, графики и сигналы.
        """
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.setupUi(self)

        # Загружаем и применяем файл стилей
        self.load_styles()

        self.selected_mode = None  # Переменная для хранения выбранного режима

        # Инициализация и настройка виджетов для графиков (pyqtgraph)
        self.graphWidget_intensity_layout = QVBoxLayout(self.graphWidget_intensity)
        self.plot_intensity = pg.PlotWidget()
        self.graphWidget_intensity_layout.addWidget(self.plot_intensity)

        self.graphWidget_traffic_direction_layout = QVBoxLayout(self.graphWidget_traffic_direction)
        self.plot_traffic_direction = pg.PlotWidget()
        self.graphWidget_traffic_direction_layout.addWidget(self.plot_traffic_direction)

        self.graphWidget_protocol_distribution_layout = QVBoxLayout(self.graphWidget_protocol_distribution)
        self.plot_protocol_distribution = pg.PlotWidget()
        self.graphWidget_protocol_distribution_layout.addWidget(self.plot_protocol_distribution)

        # Настройка заголовков и размера таблицы
        self.tableWidget_metric.setColumnCount(27)
        self.tableWidget_metric.setHorizontalHeaderLabels([
            'Время',
            'Общее число захваченных пакетов',
            'Число пакетов localhost',
            'Число пакетов broadcast/multicast',
            'Число UDP сегментов',
            'Число TCP сегментов',
            'Число пакетов с опциями',
            'Число фрагментированных пакетов',
            'Общая интенсивность пакетов',
            "Количество пакетов типа FIN",
            'Количество пакетов типа SYN',
            'Число пакетов, входящих в сеть',
            "Число UDP сегментов входящих в сеть",
            "Число TCP сегментов, входящих в сеть",
            "Число пакетов с опциями, входящих в сеть",
            "Число фрагментированных пакетов, входящих в сеть",
            "Интенсивность пакетов, входящих в сеть",
            "Количество пакетов типа FIN, входящих в сеть",
            "Количество пакетов типа SYN, входящих в сеть",
            'Число пакетов, исходящих из сети',
            "Число UDP сегментов, исходящих из сети",
            "Число TCP сегментов, исходящих из сети",
            "Число пакетов с опциями, исходящих из сети",
            "Число фрагментированных пакетов, исходящих из сети",
            "Интенсивность пакетов, исходящих из сети",
            "Количество пакетов типа FIN, исходящих из сети",
            "Количество пакетов типа SYN, исходящих из сети"
        ])
        self.tableWidget_metric.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        self.tableWidget_metric.horizontalHeader().setStretchLastSection(True)

        # FIX: Устанавливаем стиль для горизонтального, вертикального и углового заголовков
        table_header_style = "QHeaderView::section { background-color: #2b2b2b; color: #E0E0E0; }"
        self.tableWidget_metric.horizontalHeader().setStyleSheet(table_header_style)
        self.tableWidget_metric.verticalHeader().setStyleSheet(table_header_style)
        self.tableWidget_metric.setStyleSheet("QTableCornerButton::section { background-color: #2b2b2b; }")


        # Настройки графика интенсивности
        self.plot_intensity.setTitle("Интенсивность пакетов", color='#E0E0E0')
        self.plot_intensity.setLabel('left', 'Пакетов/с', units='пак/с', color='#E0E0E0')
        self.plot_intensity.setLabel('bottom', 'Интервал', color='#E0E0E0')
        self.plot_intensity.setBackground('#2b2b2b')
        self.plot_intensity.getPlotItem().getViewBox().setBackgroundColor('#3c3c3c')
        self.plot_intensity.getPlotItem().showGrid(x=True, y=True, alpha=0.5)
        self.curve_intensity = self.plot_intensity.plot(pen=pg.mkPen(color='#4CAF50', width=2))
        self.intensity_data = []
        self.interval_indices_intensity = []

        # Настройки графика входящего/исходящего трафика
        self.plot_traffic_direction.setTitle("Входящий/Исходящий трафик", color='#E0E0E0')
        self.plot_traffic_direction.setLabel('left', 'Кол-во пакетов', units='пак', color='#E0E0E0')
        self.plot_traffic_direction.setLabel('bottom', 'Интервал', color='#E0E0E0')
        self.plot_traffic_direction.setBackground('#2b2b2b')
        self.plot_traffic_direction.getPlotItem().getViewBox().setBackgroundColor('#3c3c3c')
        self.curve_input = self.plot_traffic_direction.plot(pen=pg.mkPen(color='#4CAF50', width=2), name='Входящие')
        self.curve_output = self.plot_traffic_direction.plot(pen=pg.mkPen(color='#D4E157', width=2), name='Исходящие')
        self.plot_traffic_direction.addLegend()
        self.input_packets_data = []
        self.output_packets_data = []
        self.interval_indices_traffic = []

        # Настройки графика соотношения протоколов (гистограмма)
        self.plot_protocol_distribution.setTitle("Соотношение TCP/UDP", color='#E0E0E0')
        self.plot_protocol_distribution.setLabel('left', 'Доля (%)', color='#E0E0E0')
        self.plot_protocol_distribution.setLabel('bottom', 'Протокол', color='#E0E0E0')
        self.plot_protocol_distribution.setBackground('#2b2b2b')
        self.plot_protocol_distribution.getPlotItem().getViewBox().setBackgroundColor('#3c3c3c')
        # Создаем BarGraphItem для гистограммы
        self.bar_graph_item = pg.BarGraphItem(x=[1, 2], height=[0, 0], width=0.5, brushes=['#4CAF50', '#D4E157'])
        self.plot_protocol_distribution.addItem(self.bar_graph_item)
        self.plot_protocol_distribution.getAxis('bottom').setTicks([[(1, 'TCP'), (2, 'UDP')]])
        self.plot_protocol_distribution.setXRange(0.5, 2.5)
        self.plot_protocol_distribution.setYRange(0, 100)

        # Создаем и скрываем виджеты для онлайн-режима
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

        self.thread = QtCore.QThread()  # Объект потока
        self.worker = None  # Объект Worker

        # Соединяем кнопки с соответствующими методами
        self.pushBatton_start_capture.clicked.connect(self.attempt_start_sniffing)
        self.pushBatton_start_online.clicked.connect(self.select_online_mode)
        self.pushBatton_start_offline.clicked.connect(self.select_offline_mode)
        self.pushButton_stop_capture.clicked.connect(self.stop_sniffing)
        self.pushBatton_finish_work.clicked.connect(self.close_program)
        self.pushButton_save_in_file.clicked.connect(self.save_file_as_csv)

        self.interface_display_to_internal_map = {}
        self.pushButton_save_in_file.setEnabled(False)

        # Заполняем ComboBox доступными сетевыми интерфейсами
        self.comboBox_interface_of_capture = QtWidgets.QComboBox(self.central_widget)
        self.comboBox_interface_of_capture.setObjectName("comboBox_interface_of_capture")
        self.verticalLayout_2.insertWidget(1, self.comboBox_interface_of_capture)
        self.populate_interfaces_combo_box(self.comboBox_interface_of_capture)

        self.logger.info("Приложение Form_main инициализировано.")



    def load_styles(self):
        """Загружает QSS-стили из строки (встроенная тема)."""
        style_sheet = """
        /* Основные стили для всего приложения */
        QMainWindow {
            background-color: #2b2b2b;
            color: #f0f0f0;
        }

        /* Стили для кнопок */
        QPushButton {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 10px 20px;
            font-size: 16px;
            border-radius: 5px;
        }

        QPushButton:hover {
            background-color: #45a049;
        }

        QPushButton:pressed {
            background-color: #3e8e41;
        }

        QPushButton:disabled {
            background-color: #616161;
        }

        /* Стили для текстовых полей и PlainTextEdit */
        QLineEdit, QPlainTextEdit {
            background-color: #3c3c3c;
            border: 1px solid #555555;
            color: #f0f0f0;
            padding: 5px;
            border-radius: 3px;
        }

        /* Стили для ComboBox */
        QComboBox {
            background-color: #3c3c3c;
            border: 1px solid #555555;
            color: #f0f0f0;
            border-radius: 3px;
            padding: 3px;
        }

        /* Стили для TableWidget */
        QTableWidget {
            background-color: #3c3c3c;
            gridline-color: #555555;
            color: #f0f0f0;
            selection-background-color: #4a4a4a;
            border-radius: 5px;
        }

        /* Стили для заголовков таблицы */
        QHeaderView::section {
            background-color: #444444;
            color: #f0f0f0;
            padding: 5px;
            border: 1px solid #555555;
        }

        /* Стили для PlotWidget (pyqtgraph) */
        PlotWidget {
            background-color: #1e1e1e;
            border-radius: 5px;
        }

        /* Стили для QLabel */
        QLabel {
            color: #f0f0f0;
        }

        /* Стили для QMessageBox */
        QMessageBox {
            background-color: #2b2b2b;
            color: #f0f0f0;
            border: 1px solid #555555;
        }

        QMessageBox QLabel {
            color: #f0f0f0;
        }

        QMessageBox QPushButton {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 5px 15px;
            border-radius: 3px;
            min-width: 70px;
        }

        QMessageBox QPushButton:hover {
            background-color: #45a049;
        }
        """

        self.setStyleSheet(style_sheet)
        self.logger.info("✅ Встроенные QSS-стили успешно применены.")

    def attempt_start_sniffing(self):
        """Проверяет, выбран ли режим, и запускает проверку данных."""
        if self.selected_mode is None:
            QMessageBox.information(self, "Выбор режима",
                                    "Пожалуйста, выберите режим работы: 'Online' или 'Offline', прежде чем нажимать 'Начать захват'.")
            self.logger.warning("Попытка начать захват без выбора режима.")
            return

        self.check_input_data(mode=self.selected_mode)

    def select_offline_mode(self):
        """Выбирает локальный режим работы и скрывает поля для сервера."""
        self.logger.info("Пользователь выбрал Offline-режим.")
        self.label_name_capture_display.setText("Оффлайн-режим (выбран)")
        self.label_server_address.hide()
        self.lineEdit_server_address.hide()
        self.label_server_port.hide()
        self.spinBox_server_port.hide()
        self.selected_mode = "offline"
        QMessageBox.information(self, "Режим выбран",
                                "Выбран 'Offline' режим. Введите данные и нажмите 'Начать захват'.")

    def select_online_mode(self):
        """Выбирает режим отправки данных на сервер и отображает поля для сервера."""
        self.logger.info("Пользователь выбрал Online-режим.")
        self.label_name_capture_display.setText("Онлайн-режим (выбран)")
        self.label_server_address.show()
        self.lineEdit_server_address.show()
        self.label_server_port.show()
        self.spinBox_server_port.show()
        self.selected_mode = "online"
        QMessageBox.information(self, "Режим выбран",
                                "Выбран 'Online' режим. Введите данные и нажмите 'Начать захват'.")

    def check_input_data(self, mode):
        """
        Проверяет корректность введенных пользователем данных перед запуском сниффинга.
        """
        self.logger.info(f"Начата проверка входных данных для режима: {mode}.")
        try:
            selected_display_name = self.comboBox_interface_of_capture.currentText().strip()
            self.network_cidr = self.lineEdit_network_capture.text().strip()
            self.time_of_capture = self.spinBox_time_of_capture.value()

            # Валидация полей ввода
            if not selected_display_name:
                QMessageBox.warning(self, "Предупреждение", "Необходимо выбрать сетевой интерфейс.")
                self.logger.warning("Попытка начать сниффинг без выбора интерфейса.")
                return
            elif not self.network_cidr or self.time_of_capture == 0:
                QMessageBox.warning(self, "Предупреждение",
                                    "Необходимо ввести все данные для работы (сеть и время захвата).")
                self.logger.warning("Попытка начать сниффинг без полных входных данных.")
                return

            # Проверка формата CIDR-адреса
            if '/' not in self.network_cidr:
                error_message = ("Некорректный формат адреса сети.\n"
                                 "Пожалуйста, введите адрес сети вместе с маской (например, 192.168.1.0/24).")
                QMessageBox.warning(self, "Ошибка ввода", error_message)
                self.logger.error(f"Некорректный формат сети введен: {self.network_cidr}. Отсутствует маска.")
                return

            try:
                # Проверяем, является ли строка корректным CIDR-адресом
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
        """
        Запускает процесс сниффинга в отдельном потоке.
        :param mode: Выбранный режим работы ("online" или "offline").
        """
        self.pushButton_stop_capture.setEnabled(True)
        self.logger.info(f"Попытка начать сниффинг в режиме: {mode}.")
        try:
            selected_display_name = self.comboBox_interface_of_capture.currentText().strip()
            self.interface_of_capture = self.interface_display_to_internal_map.get(
                selected_display_name, selected_display_name
            )

            self.update_status_text_zone("Начало инициализации сниффера...")
            self.logger.info("Инициализация сниффера...")

            # Блокируем кнопки, чтобы предотвратить повторный запуск
            self.pushBatton_finish_work.setEnabled(False)
            self.pushBatton_start_capture.setEnabled(False)
            self.pushBatton_start_online.setEnabled(False)
            self.pushBatton_start_offline.setEnabled(False)
            self.plainTextEdit.clear()
            self.tableWidget_metric.setRowCount(0)

            # Очищаем данные графиков
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

            # Проверяем, запущен ли поток
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

            # Создаем экземпляр Worker в зависимости от выбранного режима
            if mode == "online":
                server_address = self.lineEdit_server_address.text().strip()
                server_port = self.spinBox_server_port.value()
                self.worker = Worker(mode="online", server_address=server_address, server_port=server_port)
            else:  # mode == "offline"
                self.worker = Worker(mode="offline")

            # Перемещаем Worker в отдельный поток и соединяем сигналы со слотами
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
            # Обработка исключений при запуске сниффера
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
            self.pushBatton_start_online.setEnabled(True)
            self.pushBatton_start_offline.setEnabled(True)
            self.pushButton_stop_capture.setEnabled(False)
            self.pushBatton_finish_work.setEnabled(True)

    def stop_sniffing(self):
        """Останавливает фоновый поток сниффинга."""
        self.logger.info("Пользователь запросил остановку сниффинга.")
        try:
            if self.thread.isRunning():
                if self.worker:
                    self.worker.stop()  # Устанавливаем флаг остановки
                self.thread.quit()  # Завершаем цикл событий потока
                self.thread.wait()  # Ждем завершения потока
                self.pushButton_stop_capture.setEnabled(False)
                QMessageBox.information(self, "Сниффер", "Сниффинг остановлен.")
                self.update_status_text_zone("Сниффинг остановлен пользователем.")
                self.logger.info("Сниффинг успешно остановлен.")
                # Снимаем блокировку с кнопок
                self.pushBatton_start_capture.setEnabled(True)
                self.pushBatton_start_online.setEnabled(True)
                self.pushBatton_start_offline.setEnabled(True)
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
        # Включаем кнопки после завершения работы
        self.pushButton_save_in_file.setEnabled(True)
        self.pushBatton_finish_work.setEnabled(True)
        self.pushBatton_start_capture.setEnabled(True)
        self.pushBatton_start_online.setEnabled(True)
        self.pushBatton_start_offline.setEnabled(True)

    def save_file_as_csv(self):
        """Сохранение данных в CSV файл."""
        self.logger.info("Пользователь запросил сохранение данных в CSV.")
        try:
            if not self.worker or not self.worker.data_all_intervals:
                raise ValueError("Нет данных для сохранения.")

            options = QFileDialog.Options()
            options |= QFileDialog.DontUseNativeDialog

            # Открываем диалоговое окно для сохранения файла
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
                # Записываем заголовок
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
                # Записываем данные по интервалам
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
        # Автоматическая прокрутка к последнему сообщению
        self.plainTextEdit.verticalScrollBar().setValue(self.plainTextEdit.verticalScrollBar().maximum())
        self.logger.debug(f"Сообщение отправлено в UI: {message}")

    def update_metrics_table(self, all_metrics_data):
        """
        Обновляет таблицу агрегированных метрик.
        :param all_metrics_data: Полный список метрик от Worker.
        """
        try:
            row_position = self.tableWidget_metric.rowCount()
            self.tableWidget_metric.insertRow(row_position)
            for col, data in enumerate(all_metrics_data):
                item = QTableWidgetItem(str(data))
                self.tableWidget_metric.setItem(row_position, col, item)
            self.tableWidget_metric.scrollToBottom()
            self.logger.debug(f"Метрики добавлены в таблицу: {all_metrics_data}")
        except Exception as e:
            self.logger.error(f"Ошибка при обновлении таблицы метрик: {e}", exc_info=True)
            self.update_status_text_zone(f"ОШИБКА: Не удалось обновить таблицу метрик: {e}")

    def update_intensity_graph(self, all_metrics_data):
        """
        Обновляет график интенсивности.
        :param all_metrics_data: Полный список метрик от Worker.
        """
        try:
            intensity_value = float(all_metrics_data[8])
            self.intensity_data.append(intensity_value)
            self.interval_indices_intensity.append(len(self.interval_indices_intensity))
            max_points = 50  # Ограничение на количество отображаемых точек
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
            input_packets = float(all_metrics_data[11])
            output_packets = float(all_metrics_data[19])
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
            tcp_segments = float(all_metrics_data[5])
            udp_segments = float(all_metrics_data[4])
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
        """
        Заполняет ComboBox списком доступных сетевых интерфейсов.
        :param combo_box_widget: Виджет QComboBox для заполнения.
        """
        self.logger.info("Попытка заполнить список сетевых интерфейсов.")
        try:
            combo_box_widget.clear()
            self.interface_display_to_internal_map.clear()
            interfaces = get_working_ifaces()  # Получаем список интерфейсов
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
    # Настройка логирования
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
    form.showMaximized()
    sys.exit(app.exec_())