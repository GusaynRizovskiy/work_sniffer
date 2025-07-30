from PyQt5 import QtWidgets, QtCore
from PyQt5.QtGui import QPalette, QBrush, QPixmap
from PyQt5.QtWidgets import QMessageBox
from scapy.layers.inet import IP, UDP, TCP
from utils import address_in_network  # Ваш обновленный utils.py
from form_of_sniffer import Form1  # Ваш сгенерированный файл UI
from datetime import datetime
from scapy.all import *  # Убедитесь, что get_working_ifaces() доступен
import sys
import csv
import platform
import ipaddress  # <--- НОВОЕ: Импортируем ipaddress для валидации ввода


# Класс, который будет наследоваться от QObject и выполнять основную работу программы
class Worker(QtCore.QObject):
    finished = QtCore.pyqtSignal()  # Сигнал для указания завершения

    def __init__(self):
        super().__init__()
        self.is_running = True  # Флаг для контроля выполнения
        self.data_all_intervals = []  # Здесь хранятся агрегированные данные по всем интервалам

    def run(self):
        # Этот метод вызывается, когда поток стартует (self.thread.start())
        self.is_running = True

        while self.is_running:
            self.data_one_interval = []
            # Инициализация счетчиков пакетов для ТЕКУЩЕГО интервала агрегирования
            self.initialize_packet_counts()

            self.time_begin = datetime.now().strftime('%H:%M:%S')
            try:
                # Захват пакетов с указанным фильтром и интерфейсом
                # Scapy самостоятельно понимает CIDR-нотацию в фильтре
                sniff(filter=f"net {form.network_of_capture}", iface=form.interface_of_capture,
                      prn=self.packet_callback, store=False, timeout=form.time_of_capture)
            except Exception as e:
                print(f"Ошибка при захвате пакетов: {e}")
                self.is_running = False  # Останавливаем поток при ошибке захвата
                self.finished.emit()  # Отправляем сигнал о завершении
                return

            self.time_end = datetime.now().strftime('%H:%M:%S')

            # Расчет интенсивности и подготовка данных для этого интервала
            self.calculate_intensities()
            self.prepare_data_interval()

            # Добавление данных текущего интервала в общий список всех интервалов
            self.data_all_intervals.append(self.data_one_interval)
            print(
                "-----------------------------------Интервал агрегирования завершен--------------------------------------------")

        # Этот сигнал отправляется, когда цикл while self.is_running завершается,
        # то есть, когда сниффер полностью остановлен (например, по нажатию "Прекратить").
        self.finished.emit()  # Отправка сигнала о завершении

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

        # Счетчики входящих пакетов
        self.count_input_packets = 0
        self.count_input_udp_packets = 0
        self.count_input_tcp_packets = 0
        self.count_input_fin_packets = 0
        self.count_input_sin_packets = 0
        self.count_input_intensivity_packets = 0
        self.count_input_options_packets = 0
        self.count_input_fragment_packets = 0

        # Счетчики исходящих пакетов
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
            if form.time_of_capture > 0:  # Предотвращение деления на ноль
                self.count_input_intensivity_packets = (self.count_input_packets / form.time_of_capture)
                self.count_output_intensivity_packets = (self.count_output_packets / form.time_of_capture)
            else:
                # Если время захвата 0, интенсивность не может быть рассчитана
                self.count_input_intensivity_packets = 0
                self.count_output_intensivity_packets = 0

        except Exception as e:
            print(f"Произошла ошибка при расчете интенсивности пакетов: {e}")
            self.count_input_intensivity_packets = 0
            self.count_output_intensivity_packets = 0

    def prepare_data_interval(self):
        """Подготовка данных для текущего интервала."""
        try:
            # Сбор данных в указанном порядке для этого интервала.
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
                # Данные о входящих пакетах
                self.count_input_packets,
                self.count_input_udp_packets,
                self.count_input_tcp_packets,
                self.count_input_options_packets,
                self.count_input_fragment_packets,
                self.count_input_intensivity_packets,
                self.count_input_fin_packets,
                self.count_input_sin_packets,
                # Данные о исходящих пакетах
                self.count_output_packets,
                self.count_output_udp_packets,
                self.count_output_tcp_packets,
                self.count_output_options_packets,
                self.count_output_fragment_packets,
                self.count_output_intensivity_packets,
                self.count_output_fin_packets,
                self.count_output_sin_packets,
            ]

            # Добавление отформатированных данных в список одного интервала.
            for data in interval_data_formatting:
                self.data_one_interval.append(data)

        except Exception as e:
            print(f"Произошла ошибка при подготовке данных интервала: {e}")

    def stop(self):
        """Устанавливает флаг для остановки выполнения рабочего потока."""
        self.is_running = False

    def packet_callback(self, packet):
        """Обработка захваченного пакета."""
        try:
            # print(packet.summary()) # Для отладки, можно раскомментировать
            self.count_capture_packets += 1
            # Общая интенсивность пакетов рассчитывается в конце интервала,
            # но если нужно видеть текущую, то можно тут:
            # self.count_intensivity_packets = self.count_capture_packets / form.time_of_capture if form.time_of_capture > 0 else 0

            if packet.haslayer("IP"):
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst

                # Проверка на принадлежность широковещательному адресу
                # Также учитываем мультикаст адреса (224.0.0.0/4)
                if dst_ip == "255.255.255.255" or dst_ip.endswith(".255") or (
                        dst_ip.startswith("224.") or dst_ip.startswith("23")
                ):
                    self.count_multicast_packets += 1
                # Проверка на принадлежность локальной петле
                elif dst_ip == '127.0.0.1':
                    self.count_loopback_packets += 1
                # Проверка на входящие пакеты
                # Используем network_of_capture, которая теперь является полной CIDR-нотацией
                elif not address_in_network(src_ip, form.network_of_capture) and address_in_network(dst_ip,
                                                                                                    form.network_of_capture):
                    self.count_input_packets += 1
                    self.parametrs_input_packets_count(packet)
                # Проверка на исходящие пакеты
                elif address_in_network(src_ip, form.network_of_capture) and not address_in_network(dst_ip,
                                                                                                    form.network_of_capture):
                    self.count_output_packets += 1
                    self.parametrs_output_packets_count(packet)

                # Проверка на пакеты с опциями
                # Проверяем, что слой IP существует и у него есть опции
                if packet[IP].options:
                    self.count_options_packets += 1
                # Проверка на фрагментированные пакеты
                # Если флаг MF (More Fragments) установлен, или смещение фрагмента > 0
                if (packet[IP].flags & 0x01) or (packet[IP].frag > 0):  # 0x01 - флаг MF
                    self.count_fragment_packets += 1

                # Проверка на наличие TCP сегментов
                if packet.haslayer('TCP'):
                    self.count_tcp_segments += 1
                    # Проверка на наличие FIN в TCP
                    if packet[TCP].flags.has('F'):  # Используем has() для проверки флагов
                        self.count_fin_packets += 1
                    # Проверка на наличие SIN в TCP
                    elif packet[TCP].flags.has('S'):  # Используем has() для проверки флагов
                        self.count_sin_packets += 1

                # Проверка на наличие UDP сегментов
                elif packet.haslayer('UDP'):
                    self.count_udp_segments += 1

        except Exception as e:
            # Пропускаем пакеты, которые не могут быть разобраны, или другие ошибки
            # print(f"Произошла ошибка при обработке пакета: {e}")
            pass

    def parametrs_input_packets_count(self, packet):
        """Рассчет параметров для входящих пакетов."""
        try:
            if packet.haslayer('TCP'):
                self.count_input_tcp_packets += 1
                # Проверка на наличие FIN в TCP
                if packet[TCP].flags.has('F'):
                    self.count_input_fin_packets += 1
                # Проверка на наличие SIN в TCP
                elif packet[TCP].flags.has('S'):
                    self.count_input_sin_packets += 1
            elif packet.haslayer('UDP'):
                self.count_input_udp_packets += 1

            # Проверка на фрагментированные пакеты
            if packet.haslayer("IP") and ((packet[IP].flags & 0x01) or (packet[IP].frag > 0)):
                self.count_input_fragment_packets += 1

            # Проверка на пакеты с опциями
            if packet.haslayer("IP") and packet[IP].options:
                self.count_input_options_packets += 1

        except Exception as e:
            # print(f"Произошла ошибка при обработке входящего пакета: {e}")
            pass

    # Рассчет параметров для исходящих пакетов
    def parametrs_output_packets_count(self, packet):
        """Рассчет параметров для исходящих пакетов."""
        try:
            if packet.haslayer('TCP'):
                self.count_output_tcp_packets += 1
                # Проверка на наличие FIN в TCP
                if packet[TCP].flags.has('F'):
                    self.count_output_fin_packets += 1
                # Проверка на наличие SIN в TCP
                elif packet[TCP].flags.has('S'):
                    self.count_output_sin_packets += 1
            elif packet.haslayer('UDP'):
                self.count_output_udp_packets += 1

            # Проверка на фрагментированные пакеты
            if packet.haslayer("IP") and ((packet[IP].flags & 0x01) or (packet[IP].frag > 0)):
                self.count_output_fragment_packets += 1

            # Проверка на пакеты с опциями
            if packet.haslayer("IP") and packet[IP].options:
                self.count_output_options_packets += 1

        except Exception as e:
            # print(f"Произошла ошибка при обработке исходящего пакета: {e}")
            pass


# Основной класс, в котором происходит создание экземпляра формы и считывание данных пользователя.
class Form_main(QtWidgets.QMainWindow, Form1):

    def __init__(self):
        super().__init__()
        self.setupUi(self)
        # Создаем поток, в котором будет выполняться основная работа в дополнении к основному потоку
        self.thread = QtCore.QThread()
        # Создаем экземляр класса, унаследованный от Qobject
        self.worker = Worker()
        # Перемещаем объект в поток
        self.worker.moveToThread(self.thread)

        self.pushBatton_start_capture.clicked.connect(self.check_input_data)
        self.pushBatton_stop_sniffing.clicked.connect(self.stop_sniffing)
        self.pushBatton_finish_work.clicked.connect(self.close_program)
        self.pushButton_save_in_file.clicked.connect(self.save_file_as_csv)

        # Подключаем сигнал запуска потока к методу worker.run
        self.thread.started.connect(self.worker.run)
        # Подключаем сигнал завершения работы worker к методу on_finished
        self.worker.finished.connect(self.on_finished)

        # Словарь для сопоставления отображаемого имени с внутренним именем Scapy
        self.interface_display_to_internal_map = {}

        # Блокируем кнопку сохранения данных файл для корректной работы программы
        self.pushButton_save_in_file.setEnabled(False)

        # Заполняем QComboBox доступными сетевыми интерфейсами
        self.populate_interfaces_combo_box()

    def populate_interfaces_combo_box(self):
        """Заполняет QComboBox списком доступных сетевых интерфейсов, используя дружественные имена."""
        try:
            # Очищаем предыдущие данные
            self.comboBox_interface.clear()
            self.interface_display_to_internal_map.clear()

            interfaces = get_working_ifaces()

            if not interfaces:
                QMessageBox.warning(self, "Предупреждение", "Не найдено сетевых интерфейсов.")
                return

            for iface in interfaces:
                # Используем description как отображаемое имя, если оно есть, иначе name
                display_name = iface.description if iface.description else iface.name
                internal_name = iface.name  # Это то имя, которое Scapy ожидает для sniff()

                self.comboBox_interface.addItem(display_name)
                self.interface_display_to_internal_map[display_name] = internal_name

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось получить список интерфейсов: {e}\n"
                                                 "Убедитесь, что Scapy установлен корректно и у вас есть необходимые права.")

    def check_input_data(self):
        '''
        Метод проверяет, что введены все необходимые для работы данные;
        Если это не так, то программа не заработает.
        '''
        try:
            selected_display_name = self.comboBox_interface.currentText().strip()
            network_cidr = self.lineEdit_network_capture.text().strip()

            time_of_capture = self.spinBox_time_of_capture.value()

            # Проверка на пустые поля и минимальное значение времени захвата
            if not selected_display_name:
                QMessageBox.warning(self, "Предупреждение", "Необходимо выбрать сетевой интерфейс.")
                return
            elif not network_cidr or time_of_capture == self.spinBox_time_of_capture.minimum():
                QMessageBox.warning(self, "Предупреждение", "Необходимо ввести все данные для работы.")
                return

            # Дополнительная проверка на валидность CIDR-нотации
            try:
                ipaddress.ip_network(network_cidr, strict=False)
            except ValueError:
                QMessageBox.warning(self, "Ошибка ввода",
                                    "Некорректный формат сети. Используйте CIDR-нотацию (например, 192.168.1.0/24).")
                return

            # Если все проверки пройдены, запускаем сниффер
            self.start_sniffing()

        except ValueError as ve:
            QMessageBox.warning(self, "Ошибка ввода", str(ve))
        except Exception as e:
            print(f"Произошла ошибка: {e}")
            QMessageBox.critical(self, "Ошибка", f"Произошла непредвиденная ошибка при проверке данных: {e}")

    def start_sniffing(self):
        '''
        Метод считывает данные для работы, такие как:
            -время до которого необходимо перехватывать пакеты
            -интерфейс, по которому необходимо производить перехват
            -сеть, перехват пакетов которой необходимо произвести
        '''
        self.pushBatton_stop_sniffing.setEnabled(True)
        try:
            self.time_of_capture = self.spinBox_time_of_capture.value()

            selected_display_name = self.comboBox_interface.currentText().strip()
            self.interface_of_capture = self.interface_display_to_internal_map.get(
                selected_display_name, selected_display_name
            )

            self.network_of_capture = self.lineEdit_network_capture.text().strip()

            # Проверка на корректность введенных данных
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
            self.text_zone.clear()  # Очищаем текстовую область

            # --- ИЗМЕНЕНИЕ: Очищаем data_all_intervals перед каждым НОВЫМ запуском сниффинга ---
            self.worker.data_all_intervals.clear()
            # -----------------------------------------------------------------------------------

            if not self.thread.isRunning():
                self.thread.start()
            else:
                QMessageBox.information(self, "Информация",
                                        "Сниффер уже запущен. Сначала остановите его, чтобы начать новый захват.")
                self.pushBatton_start_capture.setEnabled(True)  # Включаем кнопку обратно, если уже запущен
                self.pushBatton_stop_sniffing.setEnabled(True)  # Убеждаемся, что кнопка стоп активна
                return  # Выходим, если сниффер уже запущен

        except ValueError as ve:
            QMessageBox.warning(self, "Ошибка ввода", str(ve))
            self.pushBatton_start_capture.setEnabled(True)  # Включаем кнопку, если была ошибка валидации
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Произошла ошибка при запуске сниффера: {e}")
            self.pushBatton_start_capture.setEnabled(True)  # Включаем кнопку, если была непредвиденная ошибка

    def stop_sniffing(self):
        """Останавливает фоновый поток сниффинга."""
        try:
            if self.thread.isRunning():
                self.worker.stop()  # Отправка сигнала для остановки Worker
                self.thread.quit()  # Завершение потока
                self.thread.wait()  # Ожидание завершения потока
                self.pushBatton_stop_sniffing.setEnabled(False)
                QMessageBox.information(self, "Сниффер", "Сниффинг остановлен.")
                # После остановки, включаем кнопку "Начать захват" и "Сохранить в файл"
                self.pushBatton_start_capture.setEnabled(True)
                self.pushButton_save_in_file.setEnabled(True)
                self.pushBatton_finish_work.setEnabled(True)
            else:
                QMessageBox.information(self, "Сниффер", "Сниффинг не был запущен.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Произошла ошибка при остановке сниффера: {e}")

    def on_finished(self):
        """Функция выполняется, когда рабочий поток Worker завершает свою работу."""
        print("Снифер завершил свою работу")
        self.pushButton_save_in_file.setEnabled(True)
        self.pushBatton_finish_work.setEnabled(True)
        self.pushBatton_start_capture.setEnabled(True)
        # Эта очистка data_all_intervals здесь больше не является основной,
        # так как она происходит в start_sniffing, но может быть оставлена как дополнительная мера
        # self.worker.data_all_intervals.clear()

    def save_file_as_csv(self):
        """Сохранение данных в CSV файл."""
        try:
            # Проверяем, есть ли данные для сохранения
            if not self.worker.data_all_intervals:
                raise ValueError("Нет данных для сохранения.")

            # Открываем файл для записи
            with open('data.csv', 'w', newline='', encoding='windows-1251') as file:
                writer = csv.writer(file)
                # Записываем заголовки
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
                # Записываем данные из списков
                for i in range(len(self.worker.data_all_intervals)):
                    writer.writerow(self.worker.data_all_intervals[i])

            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Information)
            msg_box.setText("Данные успешно сохранены в файл data.csv в директории проекта!")
            msg_box.setWindowTitle("Успех")
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.exec_()

        except ValueError as ve:
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setText(str(ve))
            msg_box.setWindowTitle("Ошибка")
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.exec_()
        except Exception as e:
            print(f"Произошла ошибка при сохранении файла: {e}")
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Critical)
            msg_box.setText(f"Произошла ошибка при сохранении данных: {e}")
            msg_box.setWindowTitle("Ошибка")
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.exec_()

    def close_program(self):
        """Функция отвечающая за закрытие программы."""
        try:
            if self.thread.isRunning():
                self.worker.stop()
                self.thread.quit()
                self.thread.wait()

            self.close()

        except Exception as e:
            print(f"Произошла ошибка при закрытии программы: {e}")


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    form = Form_main()
    palette = QPalette()
    palette.setBrush(QPalette.Background, QBrush(QPixmap("fon/picture_fon.jpg")))
    form.setPalette(palette)
    form.show()
    sys.exit(app.exec_())