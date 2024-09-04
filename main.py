from PyQt5 import QtWidgets
from PyQt5.QtGui import QPalette, QBrush, QPixmap
from PyQt5.QtWidgets import  QMessageBox
from scapy.layers.inet import IP, UDP, TCP
from utils import address_in_network
from form_of_sniffer import Form1
from scapy.all import *
import sys
import csv
#Основной класс, в котором происходит создание экземляра формы и считывание данных пользователя
class Form_main(QtWidgets.QMainWindow,Form1):

    def __init__(self):
        '''
           def __init__(self) предназначен для инициализации класса
           Последние две команды метода связывают кнопки начала и завершения с нажатиме на них
        '''
        super().__init__()
        self.setupUi(self)

        self.pushBatton_start_capture.clicked.connect(self.check_input_data)
        self.pushBatton_finish_work.clicked.connect(self.close_program)
        self.pushButton_save_in_file.clicked.connect(self.save_file_as_csv)

        #Блокируем кнопку сохранения данных файл для корректной работы программы
        self.pushButton_save_in_file.setEnabled(False)

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
        В конеце метода происходит запус самого сниффера, в качестве аргумента
        передается интерфейс перехвата
        :return:
        '''
        self.time_of_capture = self.spinBox_time_of_capture.value()
        self.interface_of_capture = self.lineEdit_interface_capture.text()
        self.network_of_capture = self.lineEdit_network_capture.text()

        #Переменные, в которых будут хранится данные о количестве различных пакетов
        self.count_loopback_packets = 0
        self.count_capture_packets = 0
        self.count_multicast_packets = 0
        self.count_input_packets = 0
        self.count_output_packets = 0
        self.count_udp_segments = 0
        self.count_tcp_segments = 0
        self.count_options_packets = 0
        self.count_fragment_packets = 0
        self.count_intensivity_packets = 0
        self.count_fin_packets = 0
        self.count_sin_packets = 0
        self.data = {}

        #После каждого запуска снифера предыдущие данные будут очищаться
        self.text_zone.clear()

        'Вызов функция, запускающей сниффер'
        start_sniffer(interface=self.interface_of_capture)

        #Разблокируем кнопку сохранения данных в файл
        self.pushButton_save_in_file.setEnabled(True)

        #Отображаем количество всех захваченных пакетов
        self.label_count_capture_packets.setText(f"{self.count_capture_packets}")
        #Отображаем количество захваченных пакетов loopback
        self.label_count_holentet_packets.setText(f"{self.count_loopback_packets}")
        # Отображаем количество захваченных пакетов broadcast
        self.label_count_multicast_packets.setText(f"{self.count_multicast_packets}")
        #Отображаем количество пакетов входящих в нашу сеть
        self.label_count_input_packets.setText(f"{self.count_input_packets}")
        # Отображаем количество пакетов исходящих из нашей сеть
        self.label_count_output_packets.setText(f"{self.count_output_packets}")
        # Отображаем количество udp сегментов
        self.label_count_udp_segments.setText(f"{self.count_udp_segments}")
        # Отображаем количество tcp сегментов
        self.label_count_tcp_segments.setText(f"{self.count_tcp_segments}")
        # Отображаем количество пакетов с опциями
        self.label_count_options_packets.setText(f"{self.count_options_packets}")
        # Отображаем количество пакетов  фрагментированных
        self.label_count_fragment_packets.setText(f"{self.count_fragment_packets}")
        # Отображаем интенсивность пакетов
        self.label_intensivity_packets.setText(f"{self.count_intensivity_packets}")
        # Отображаем количество пакетов Fin
        self.label_count_fin_packets.setText(f"{self.count_fin_packets}")
        # Отображаем количество пакетов SIN
        self.label_count_sin_packets.setText(f"{self.count_sin_packets}")

        #Добавляем данные в словарь, чтобы впоследствии сохранить их в формате csv
        self.data["Общее число захваченных пакетов:"] = self.count_capture_packets
        self.data["Число пакетов localhost:"] = self.count_loopback_packets
        self.data["Число пакетов broadcast:"] = self.count_multicast_packets
        self.data["Число пакетов, входящих в сеть:"] = self.count_input_packets
        self.data["Число пакетов, исходящих из сети:"] = self.count_output_packets
        self.data["Число UDP сегментов:"] = self.count_udp_segments
        self.data["Число TCP сегментов:"] = self.count_tcp_segments
        self.data["Число пакетов с опциями:"] = self.count_options_packets
        self.data["Число фрагментированных пакетов:"] = self.count_fragment_packets
        self.data["Общая интенсивность пакетов:"] = self.count_intensivity_packets
        self.data["Количество пакетов типа FIN:"] = self.count_fin_packets
        self.data["Количество пакетов типа SIN:"] = self.count_sin_packets

    #Функция реализующая сохранение данных в формате csv
    def save_file_as_csv(self):
        # Открываем файл для записи
        with open('data.csv', 'w', newline='', encoding='windows-1251') as file:
            writer = csv.writer(file)
            # Записываем заголовки
            writer.writerow(['Параметр перехвата', 'Количество перехваченных объектов'])
            # Записываем данные из словаря
            for key, value in self.data.items():
                writer.writerow([key, value])
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Information)  # Устанавливаем иконку
        msg_box.setText("Данные успешно сохранены в директории проекта!")  # Основной текст
        msg_box.setWindowTitle("Успех")  # Заголовок окна
        msg_box.setStandardButtons(QMessageBox.Ok)  # Кнопка "ОК"
        # Отображаем сообщение
        msg_box.exec_()

    def close_program(self):
        'Функция отвечающая за закрытие программы'
        self.close()



# Функция для обработки перехваченных пакетов
def packet_callback(packet):
    print(packet.summary())
    form.count_capture_packets+=1
    form.count_intensivity_packets = form.count_capture_packets/form.time_of_capture
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        # Проверка на принадлежность широковещательному адресу
        if dst_ip == "255.255.255.255" or dst_ip.endswith(".255"):
            form.count_multicast_packets += 1
        # Проверка на принадлежность локальной петле
        elif dst_ip == '127.0.0.1':
            form.count_loopback_packets += 1
        # Проверка на входящие пакеты
        elif not address_in_network(src_ip,f"{form.network_of_capture}/24") and address_in_network(dst_ip,f"{form.network_of_capture}/24"):
            form.count_input_packets += 1
        # Проверка на исходящие пакеты
        elif  address_in_network(src_ip,f"{form.network_of_capture}/24") and not address_in_network(dst_ip,f"{form.network_of_capture}/24"):
            form.count_output_packets += 1
        # Проверка на пакеты с опциями
        if packet[IP].options:
            form.count_options_packets += 1
        # Проверка на фрагменированные пакеты
        if packet[IP].frag > 0:
            form.count_fragment_packets += 1
        # Проверка на наличие TCP сегментов
        if packet.haslayer('TCP'):
            form.count_tcp_segments += 1
            # Проверка на наличие FIN в TCP
            if packet[TCP].flags == 'F':
                form.count_fin_packets += 1
            # Проверка на наличие SIN в TCP
            elif packet[TCP].flags == 'S':
                form.count_sin_packets += 1
        # Проверка на наличие UDP сегментов
        elif packet.haslayer('UDP'):
            form.count_udp_segments += 1



#Функция запускающая сканирование и перехват пакетов(сниффинг)
def start_sniffer(interface):
    print("Запуск сниффера пакетов...")
    sniff(filter=f"net {form.network_of_capture}/24",iface=interface, prn=packet_callback, store=False,timeout=form.time_of_capture)
if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    form = Form_main()
    palette = QPalette()
    palette.setBrush(QPalette.Background, QBrush(QPixmap("picture_fon.jpg")))
    form.setPalette(palette)
    form.show()
    sys.exit(app.exec_())

#проверка работы
#proverka