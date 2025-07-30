# -*- coding: utf-8 -*-
import logging
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtGui import QPalette, QBrush, QPixmap
from PyQt5.QtWidgets import QMessageBox, QFileDialog
from scapy.layers.inet import IP, UDP, TCP
from utils import address_in_network
from form_of_sniffer import Form1  # Убедитесь, что form_of_sniffer.py находится в той же директории
from datetime import datetime
from scapy.all import *
import sys
import csv
import platform
import ipaddress


# Класс, который будет наследоваться от QObject и выполнять основную работу программы
class Worker(QtCore.QObject):
    finished = QtCore.pyqtSignal()  # Сигнал для указания завершения
    status_update = QtCore.pyqtSignal(str)  # Сигнал для обновления статуса в text_zone (общие сообщения)
    packet_info_update = QtCore.pyqtSignal(str)  # Новый сигнал для информации о перехваченных пакетах

    def __init__(self):
        super().__init__()
        self.is_running = True  # Флаг для контроля выполнения
        self.data_all_intervals = []  # Здесь хранятся агрегированные данные по всем интервалам

    def run(self):
        self.is_running = True
        self.status_update.emit("Сниффинг запущен...")

        while self.is_running:
            self.data_one_interval = []
            self.initialize_packet_counts()

            self.time_begin = datetime.now().strftime('%H:%M:%S')
            self.status_update.emit(
                f"Начало интервала агрегирования: {self.time_begin} (длительность {form.time_of_capture} с.)")

            try:
                sniff(filter=f"net {form.network_of_capture}", iface=form.interface_of_capture,
                      prn=self.packet_callback, store=False, timeout=form.time_of_capture)
            except Exception as e:
                self.status_update.emit(
                    f"КРИТИЧЕСКАЯ ОШИБКА: Ошибка в процессе захвата пакетов: {e}. Сниффинг остановлен.")
                self.is_running = False
                self.finished.emit()
                return

            self.time_end = datetime.now().strftime('%H:%M:%S')

            self.calculate_intensities()
            self.prepare_data_interval()

            self.data_all_intervals.append(self.data_one_interval)
            self.status_update.emit("Интервал агрегирования завершен")

        self.finished.emit()

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

    def calculate_intensities(self):
        """Расчет интенсивности входящих и исходящих пакетов."""
        try:
            if form.time_of_capture > 0:
                self.count_input_intensivity_packets = (self.count_input_packets / form.time_of_capture)
                self.count_output_intensivity_packets = (self.count_output_packets / form.time_of_capture)
            else:
                self.count_input_intensivity_packets = 0
                self.count_output_intensivity_packets = 0

        except Exception as e:
            self.status_update.emit(f"ОШИБКА: Произошла ошибка при расчете интенсивности пакетов: {e}")
            self.count_input_intensivity_packets = 0
            self.count_output_intensivity_packets = 0

    def prepare_data_interval(self):
        """Подготовка данных для текущего интервала."""
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

            for data in interval_data_formatting:
                self.data_one_interval.append(data)

        except Exception as e:
            self.status_update.emit(f"ОШИБКА: Произошла ошибка при подготовке данных интервала: {e}")

    def stop(self):
        """Устанавливает флаг для остановки выполнения рабочего потока."""
        self.is_running = False

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
                elif not address_in_network(src_ip, form.network_of_capture) and address_in_network(dst_ip,
                                                                                                    form.network_of_capture):
                    self.count_input_packets += 1
                    self.parametrs_input_packets_count(packet)
                elif address_in_network(src_ip, form.network_of_capture) and not address_in_network(dst_ip,
                                                                                                    form.network_of_capture):
                    self.count_output_packets += 1
                    self.parametrs_output_packets_count(packet)

                if packet[IP].options:
                    self.count_options_packets += 1
                if (packet[IP].flags & 0x01) or (packet[IP].frag > 0):
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
            self.status_update.emit(f"ПРЕДУПРЕЖДЕНИЕ: Ошибка при обработке пакета: {e}. Пакет пропущен.")
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
            pass


# Основной класс, в котором происходит создание экземпляра формы и считывание данных пользователя.
class Form_main(QtWidgets.QMainWindow, Form1):

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)  # Оставлен логгер только в Form_main
        self.setupUi(self)
        self.thread = QtCore.QThread()
        self.worker = Worker()
        self.worker.moveToThread(self.thread)

        self.pushBatton_start_capture.clicked.connect(self.check_input_data)
        self.pushBatton_stop_sniffing.clicked.connect(self.stop_sniffing)
        self.pushBatton_finish_work.clicked.connect(self.close_program)
        self.pushButton_save_in_file.clicked.connect(self.save_file_as_csv)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_finished)
        self.worker.status_update.connect(self.update_status_text_zone)
        self.worker.packet_info_update.connect(self.update_status_text_zone)

        self.interface_display_to_internal_map = {}
        self.pushButton_save_in_file.setEnabled(False)
        self.populate_interfaces_combo_box()

    def update_status_text_zone(self, message):
        """Добавляет сообщение в текстовую область с временной меткой и прокручивает его."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        formatted_message = f"[{timestamp}] {message}"
        # ИСПРАВЛЕНИЕ: Используем appendPlainText, как того требует TextEditLogger
        self.text_zone.appendPlainText(formatted_message)
        self.text_zone.verticalScrollBar().setValue(self.text_zone.verticalScrollBar().maximum())

    def populate_interfaces_combo_box(self):
        """Заполняет QComboBox списком доступных сетевых интерфейсов, используя дружественные имена."""
        try:
            self.comboBox_interface.clear()
            self.interface_display_to_internal_map.clear()

            interfaces = get_working_ifaces()

            if not interfaces:
                QMessageBox.warning(self, "Предупреждение", "Не найдено сетевых интерфейсов.")
                self.logger.warning("Не найдено сетевых интерфейсов.")  # Логируем
                return

            for iface in interfaces:
                display_name = iface.description if iface.description else iface.name
                internal_name = iface.name

                self.comboBox_interface.addItem(display_name)
                self.interface_display_to_internal_map[display_name] = internal_name
                self.logger.info(f"Найден интерфейс: {display_name} (Внутреннее имя: {internal_name})")  # Логируем

        except Exception as e:
            self.logger.critical(f"Не удалось получить список сетевых интерфейсов: {e}",
                                 exc_info=True)  # Логируем критическую ошибку
            QMessageBox.critical(self, "Ошибка загрузки интерфейсов",
                                 f"Не удалось получить список сетевых интерфейсов: {e}\n"
                                 "Пожалуйста, убедитесь, что WinPcap/Npcap установлен(а) (для Windows) и у программы есть необходимые права (например, запуск от имени администратора).")

    def check_input_data(self):
        try:
            selected_display_name = self.comboBox_interface.currentText().strip()
            network_cidr = self.lineEdit_network_capture.text().strip()
            time_of_capture = self.spinBox_time_of_capture.value()

            if not selected_display_name:
                QMessageBox.warning(self, "Предупреждение", "Необходимо выбрать сетевой интерфейс.")
                return
            elif not network_cidr or time_of_capture == self.spinBox_time_of_capture.minimum():
                QMessageBox.warning(self, "Предупреждение", "Необходимо ввести все данные для работы.")
                return

            try:
                ipaddress.ip_network(network_cidr, strict=False)
            except ValueError:
                QMessageBox.warning(self, "Ошибка ввода",
                                    "Некорректный формат сети. Используйте CIDR-нотацию (например, 192.168.1.0/24).")
                return

            self.start_sniffing()

        except ValueError as ve:
            QMessageBox.warning(self, "Ошибка ввода", str(ve))
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Произошла непредвиденная ошибка при проверке данных: {e}")

    def start_sniffing(self):
        self.pushBatton_stop_sniffing.setEnabled(True)
        try:
            self.time_of_capture = self.spinBox_time_of_capture.value()

            selected_display_name = self.comboBox_interface.currentText().strip()
            self.interface_of_capture = self.interface_display_to_internal_map.get(
                selected_display_name, selected_display_name
            )

            self.network_of_capture = self.lineEdit_network_capture.text().strip()

            self.update_status_text_zone("Начало инициализации сниффера...")

            if not self.time_of_capture > 0:
                raise ValueError("Время захвата должно быть больше нуля.")
            if not self.interface_of_capture:
                raise ValueError("Необходимо выбрать интерфейс для захвата.")
            if not self.network_of_capture:
                raise ValueError("Необходимо указать сеть для захвата.")
            try:
                ipaddress.ip_network(self.network_of_capture, strict=False)
            except ValueError:
                raise ValueError("Некорректный формат сети. Используйте CIDR-нотацию (например, 192.168.1.0/24).")

            self.pushBatton_finish_work.setEnabled(False)
            self.pushBatton_start_capture.setEnabled(False)
            self.text_zone.clear()

            self.worker.data_all_intervals.clear()

            if not self.thread.isRunning():
                self.thread.start()
            else:
                QMessageBox.information(self, "Информация",
                                        "Сниффер уже запущен. Сначала остановите его, чтобы начать новый захват.")
                self.update_status_text_zone("ПРЕДУПРЕЖДЕНИЕ: Сниффер уже запущен.")
                self.pushBatton_start_capture.setEnabled(True)
                self.pushBatton_stop_sniffing.setEnabled(True)
                return

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
            self.pushBatton_start_capture.setEnabled(True)
            self.pushBatton_stop_sniffing.setEnabled(False)
            self.pushBatton_finish_work.setEnabled(True)

    def stop_sniffing(self):
        """Останавливает фоновый поток сниффинга."""
        try:
            if self.thread.isRunning():
                self.worker.stop()
                self.thread.quit()
                self.thread.wait()
                self.pushBatton_stop_sniffing.setEnabled(False)
                QMessageBox.information(self, "Сниффер", "Сниффинг остановлен.")
                self.update_status_text_zone("Сниффинг остановлен пользователем.")
                self.pushBatton_start_capture.setEnabled(True)
                self.pushButton_save_in_file.setEnabled(True)
                self.pushBatton_finish_work.setEnabled(True)
            else:
                QMessageBox.information(self, "Сниффер", "Сниффинг не был запущен.")
                self.update_status_text_zone("ПРЕДУПРЕЖДЕНИЕ: Попытка остановить не запущенный сниффер.")
        except Exception as e:
            self.update_status_text_zone(f"ОШИБКА: Произошла ошибка при остановке сниффера: {e}")
            QMessageBox.critical(self, "Ошибка", f"Произошла ошибка при остановке сниффера: {e}")

    def on_finished(self):
        """Функция выполняется, когда рабочий поток Worker завершает свою работу."""
        self.update_status_text_zone("Сниффер завершил свою работу.")
        self.pushButton_save_in_file.setEnabled(True)
        self.pushBatton_finish_work.setEnabled(True)
        self.pushBatton_start_capture.setEnabled(True)

    def save_file_as_csv(self):
        """Сохранение данных в CSV файл."""
        try:
            if not self.worker.data_all_intervals:
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
                return

            if not file_name.endswith('.csv'):
                file_name += '.csv'

            self.update_status_text_zone(f"Начато сохранение данных в файл: {file_name}")
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

            QMessageBox.information(self, "Успех", f"Данные успешно сохранены в файл: {file_name}")
            self.update_status_text_zone(f"Данные успешно сохранены в: {file_name}")

        except ValueError as ve:
            self.update_status_text_zone(f"ОШИБКА: Ошибка при сохранении файла (нет данных): {ve}")
            QMessageBox.warning(self, "Ошибка", str(ve))
        except Exception as e:
            self.update_status_text_zone(f"КРИТИЧЕСКАЯ ОШИБКА: Произошла при сохранении файла: {e}")
            QMessageBox.critical(self, "Ошибка", f"Произошла ошибка при сохранении данных: {e}")

    def close_program(self):
        """Функция отвечающая за закрытие программы."""
        try:
            if self.thread.isRunning():
                self.worker.stop()
                self.thread.quit()
                self.thread.wait()

            self.close()

        except Exception as e:
            pass


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        stream=sys.stdout)

    app = QtWidgets.QApplication(sys.argv)
    form = Form_main()
    palette = QPalette()
    palette.setBrush(QPalette.Background, QBrush(QPixmap("fon/picture_fon.jpg")))
    form.setPalette(palette)
    form.show()
    sys.exit(app.exec_())