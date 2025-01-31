from PyQt5 import QtWidgets, QtCore
from PyQt5.QtGui import QPalette, QBrush, QPixmap
from PyQt5.QtWidgets import  QMessageBox
from scapy.layers.inet import IP, UDP, TCP
from utils import address_in_network
from form_of_sniffer import Form1
from datetime import datetime
from scapy.all import *
import sys
import csv

#Класс, который будет наследоваться от Qobject и выполнять основную работу программы
class Worker(QtCore.QObject):
    finished = QtCore.pyqtSignal()  # Сигнал для завершения работы

    def __init__(self):
        super().__init__()
        self.is_running = True  # Флаг для контроля выполнения
    def run(self):
        self.is_running = True
        self.data_all_intervals = []
        while self.is_running:
            self.data_one_interval = []
            # Переменные, в которых будут хранится данные о количестве различных пакетов
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
            # Все параметры касательно пакетов, входящих в сеть
            self.count_input_packets = 0
            self.count_input_udp_packets = 0
            self.count_input_tcp_packets = 0
            self.count_input_fin_packets = 0
            self.count_input_sin_packets = 0
            self.count_input_intensivity_packets = 0
            self.count_input_options_packets = 0
            self.count_input_fragment_packets = 0
            # Все параметры касательно пакетов, исходящих из сети
            self.count_output_packets = 0
            self.count_output_udp_packets = 0
            self.count_output_tcp_packets = 0
            self.count_output_fin_packets = 0
            self.count_output_sin_packets = 0
            self.count_output_intensivity_packets = 0
            self.count_output_options_packets = 0
            self.count_output_fragment_packets = 0
            #Время начала захвата
            self.time_begin = datetime.now().strftime('%H:%M:%S')
            # Выполнение длительной задачи
            sniff(filter=f"net {form.network_of_capture}/24", iface=form.interface_of_capture,
                  prn=self.packet_callback, store=False, timeout=form.time_of_capture)
            # Время окончания захвата
            self.time_end = datetime.now().strftime('%H:%M:%S')
            # Подсчет интенсивности входящих и исходящих пакетов.
            self.count_input_intensivity_packets = self.count_input_packets / form.time_of_capture
            self.count_output_intensivity_packets = self.count_output_packets / form.time_of_capture

            # Добавляем данные за данный интервал в список, чтобы позже добавить общий список интервалов
            # Данные в список добавляются в следующем порядке:

            #Время захвата первого пакета
            self.data_one_interval.append(f"{self.time_begin}-{self.time_end}")
            # -Общее число захваченных пакетов #
            self.data_one_interval.append(self.count_capture_packets)
            # -Число пакетов localhost
            self.data_one_interval.append(self.count_loopback_packets)
            # -Число пакетов broadcast
            self.data_one_interval.append(self.count_multicast_packets)
            # -Общее число UDP сегментов
            self.data_one_interval.append(self.count_udp_segments)
            # -Общее число TCP сегментов
            self.data_one_interval.append(self.count_tcp_segments)
            # -Общее число пакетов с опциями
            self.data_one_interval.append(self.count_options_packets)
            # -Общее число фрагментированных пакетов
            self.data_one_interval.append(self.count_fragment_packets)
            # -Общая интенсивность пакетов
            self.data_one_interval.append(self.count_intensivity_packets)
            # -Общее количество пакетов типа FIN
            self.data_one_interval.append(self.count_fin_packets)
            # -Общее количество пакетов типа SIN
            self.data_one_interval.append(self.count_sin_packets)
            # -Число пакетов, входящих в сеть
            self.data_one_interval.append(self.count_input_packets)
            # -Число UDP сегментов входящих в сеть
            self.data_one_interval.append(self.count_input_udp_packets)
            # -Число TCP сегментов, входящих в сеть
            self.data_one_interval.append(self.count_input_tcp_packets)
            # -Число пакетов с опциями, входящих в сеть
            self.data_one_interval.append(self.count_input_options_packets)
            # -Число фрагментированных пакетов, входящих в сеть
            self.data_one_interval.append(self.count_input_fragment_packets)
            # -Интенсивность пакетов, входящих в сеть
            self.data_one_interval.append(self.count_input_intensivity_packets)
            # -Количество пакетов типа FIN, входящих в сеть
            self.data_one_interval.append(self.count_input_fin_packets)
            # -Количество пакетов типа SIN, входящих в сеть
            self.data_one_interval.append(self.count_input_sin_packets)
            # -Число пакетов, исходящих из сети
            self.data_one_interval.append(self.count_output_packets)
            # -Число UDP сегментов, исходящих из сети
            self.data_one_interval.append(self.count_output_udp_packets)
            # -Число TCP сегментов, исходящих из сети
            self.data_one_interval.append(self.count_output_tcp_packets)
            # -Число пакетов с опциями, исходящих из сети
            self.data_one_interval.append(self.count_output_options_packets)
            # -Число фрагментированных пакетов, исходящих из сети
            self.data_one_interval.append(self.count_output_fragment_packets)
            # -Интенсивность пакетов, исходящих из сети
            self.data_one_interval.append(self.count_output_intensivity_packets)
            # -Количество пакетов типа FIN, исходящих из сети
            self.data_one_interval.append(self.count_output_fin_packets)
            # -Количество пакетов типа SIN, исходящих из сети
            self.data_one_interval.append(self.count_output_sin_packets)

            #Добавляем информацию об одном интервале в список всех интервалов
            self.data_all_intervals.append(self.data_one_interval)
            print("-----------------------------------Интервал агрегирования завершен--------------------------------------------")
        self.finished.emit()  # Отправка сигнала о завершении

    def stop(self):
        self.is_running = False  # Установка флага для остановки

    def packet_callback(self,packet):
        print(packet)
        self.count_capture_packets += 1
        self.count_intensivity_packets = self.count_capture_packets / form.time_of_capture
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            # Проверка на принадлежность широковещательному адресу
            if dst_ip == "255.255.255.255" or dst_ip.endswith(".255"):
                self.count_multicast_packets += 1
            # Проверка на принадлежность локальной петле
            elif dst_ip == '127.0.0.1':
                self.count_loopback_packets += 1
            # Проверка на входящие пакеты
            elif not address_in_network(src_ip, f"{form.network_of_capture}/24") and address_in_network(dst_ip, f"{form.network_of_capture}/24"):
                self.count_input_packets += 1
                self.parametrs_input_packets_count(packet)
            # Проверка на исходящие пакеты
            elif address_in_network(src_ip, f"{form.network_of_capture}/24") and not address_in_network(dst_ip, f"{form.network_of_capture}/24"):
                self.count_output_packets += 1
                self.parametrs_output_packets_count(packet)
            # Проверка на пакеты с опциями
            if packet[IP].options:
                self.count_options_packets += 1
            # Проверка на фрагменированные пакеты
            if packet[IP].frag > 0:
                self.count_fragment_packets += 1
            # Проверка на наличие TCP сегментов
            if packet.haslayer('TCP'):
                self.count_tcp_segments += 1
                # Проверка на наличие FIN в TCP
                if packet[TCP].flags == 'F':
                    self.count_fin_packets += 1
                # Проверка на наличие SIN в TCP
                elif packet[TCP].flags == 'S':
                    self.count_sin_packets += 1
            # Проверка на наличие UDP сегментов
            elif packet.haslayer('UDP'):
                self.count_udp_segments += 1

    def parametrs_input_packets_count(self,packet):
        if packet.haslayer('TCP'):
            self.count_input_tcp_packets += 1
            # Проверка на наличие FIN в TCP
            if packet[TCP].flags == 'F':
                self.count_input_fin_packets += 1
            # Проверка на наличие SIN в TCP
            elif packet[TCP].flags == 'S':
                self.count_input_sin_packets += 1
        elif packet.haslayer('UDP'):
            self.count_input_udp_packets += 1
        if packet[IP].frag > 0:
            self.count_input_fragment_packets += 1
            # Проверка на пакеты с опциями
        if packet[IP].options:
            self.count_input_options_packets += 1

    # Рассчет параметров для исходящих пакетов
    def parametrs_output_packets_count(self,packet):
        if packet.haslayer('TCP'):
            self.count_output_tcp_packets += 1
            # Проверка на наличие FIN в TCP
            if packet[TCP].flags == 'F':
                self.count_output_fin_packets += 1
            # Проверка на наличие SIN в TCP
            elif packet[TCP].flags == 'S':
                self.count_output_sin_packets += 1
        elif packet.haslayer('UDP'):
            self.count_output_udp_packets += 1
        if packet[IP].frag > 0:
            self.count_output_fragment_packets += 1
            # Проверка на пакеты с опциями
        if packet[IP].options:
            self.count_output_options_packets += 1


#Основной класс, в котором происходит создание экземляра формы и считывание данных пользователя.
class Form_main(QtWidgets.QMainWindow,Form1):

    def __init__(self):
        '''
           def __init__(self) предназначен для инициализации класса
           Последние две команды метода связывают кнопки начала и завершения с нажатием на них
        '''
        super().__init__()
        self.setupUi(self)
        #Создаем поток, в котором будет выполняться основная работа в дополнении к основному потоку
        self.thread = QtCore.QThread()
        #Создаем экземляр класса, унаследованный от Qobject
        self.worker = Worker()
        #Перемащаем объект в поток
        self.worker.moveToThread(self.thread)

        self.pushBatton_start_capture.clicked.connect(self.check_input_data)
        self.pushBatton_stop_sniffing.clicked.connect(self.stop_sniffing)
        self.pushBatton_finish_work.clicked.connect(self.close_program)
        self.pushButton_save_in_file.clicked.connect(self.save_file_as_csv)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_finished)


        #Блокируем кнопку сохранения данных файл для корректной работы программы
        self.pushButton_save_in_file.setEnabled(False)
        #Список, в котором будет сохраняться характеристики за каждый интервал агрегирования
    def check_input_data(self):
        '''
        Метод проверяет что введены все необходимые для работы данные;
        Если это не так то программа не заработает
        :return:
        '''
        if self.lineEdit_interface_capture.text() == '' or self.lineEdit_network_capture.text() == '' or self.spinBox_time_of_capture.value() == self.spinBox_time_of_capture.minimum():
            mess_box = QMessageBox()
            mess_box.setWindowTitle("Предупреждение")
            mess_box.setText("Необходимо ввести все данные для работы")
            mess_box.setInformativeText("Заполните все входные данные")
            mess_box.setIcon(QMessageBox.Warning)
            mess_box.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
            mess_box.show()
            mess_box.exec_()
        else:
            self.start_sniffing()

    def start_sniffing(self):
        '''
        Метод считывает данные для работы, такие как:
            -время до которого необходимо перехватывать пакеты
            -интерфейс, по которому необходимо производить перехват
            -сеть, перехват пакетов которой необходимо произвести
        :return:
        '''
        self.time_of_capture = self.spinBox_time_of_capture.value()
        self.interface_of_capture = self.lineEdit_interface_capture.text()
        self.network_of_capture = self.lineEdit_network_capture.text()
        self.pushBatton_finish_work.setEnabled(False)
        self.pushBatton_start_capture.setEnabled(False)
        self.text_zone.clear()
        #Запускаем фоновый поток, в котором выполняются все операции
        if not self.thread.isRunning():
            self.thread.start()
    #Останавливаем фоновый поток
    def stop_sniffing(self):
        if self.thread.isRunning():
            self.worker.stop()  # Отправка сигнала для остановки
            self.thread.quit()  # Завершение потока
            self.thread.wait()  # Ожидание завершения потока
            self.pushBatton_stop_sniffing.setEnabled(False)
    #функция выолняется при завершении работы сниффера
    def on_finished(self):
        print("Снифер завершил свою работу")
        self.pushButton_save_in_file.setEnabled(True)
        self.pushBatton_finish_work.setEnabled(True)
        self.pushBatton_start_capture.setEnabled(True)
    #Функция реализующая сохранение данных в формате csv
    # В перспективе можно организовать сохранение в определенную директрорию с возможностью ее выбора
    def save_file_as_csv(self):
        # Открываем файл для записи
        with open('data.csv', 'w', newline='', encoding='windows-1251') as file:
            writer = csv.writer(file)
            # Записываем заголовки
            writer.writerow([
                            'Время захвата пакетов',
                            'Общее число захваченных пакетов','Число пакетов localhost','Число пакетов broadcast',
                             'Число UDP сегментов', 'Число TCP сегментов', 'Число пакетов с опциями',
                             'Число фрагментированных пакетов', 'Общая интенсивность пакетов',
                             "Количество пакетов типа FIN", 'Количество пакетов типа SIN',
                             'Число пакетов, входящих в сеть',"Число UDP сегментов входящих в сеть",
                             "Число TCP сегментов, входящих в сеть", "Число пакетов с опциями, входящих в сеть",
                             "Число фрагментированных пакетов, входящих в сеть", "Интенсивность пакетов, входящих в сеть",
                             "Количество пакетов типа FIN, входящих в сеть", "Количество пакетов типа SIN, входящих в сеть",
                             'Число пакетов, исходящих из сети', "Число UDP сегментов, исходящих из сети",
                             "Число TCP сегментов, исходящих из сети", "Число пакетов с опциями, исходящих из сети",
                             "Число фрагментированных пакетов, исходящих из сети", "Интенсивность пакетов, исходящих из сети",
                             "Количество пакетов типа FIN, исходящих из сети", "Количество пакетов типа SIN, исходящих из сети",
                             ])
            # Записываем данные из списков
            print(self.worker.data_all_intervals)
            for i in range(len(self.worker.data_all_intervals)):
                writer.writerow(self.worker.data_all_intervals[i])

        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Information)  # Устанавливаем иконку
        msg_box.setText("Данные успешно сохранены в директории проекта!")  # Основной текст
        msg_box.setWindowTitle("Успех")  # Заголовок окна
        msg_box.setStandardButtons(QMessageBox.Ok)  # Кнопка "ОК"
        # Отображаем сообщение
        msg_box.exec_()

    def close_program(self):
        self.worker.data_all_intervals.clear()
        'Функция отвечающая за закрытие программы'
        self.close()

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    form = Form_main()
    palette = QPalette()
    palette.setBrush(QPalette.Background, QBrush(QPixmap("fon/picture_fon.jpg")))
    form.setPalette(palette)
    form.show()
    sys.exit(app.exec_())

