from PyQt5 import QtWidgets
from PyQt5.QtWidgets import  QMessageBox
from scapy.layers.inet import IP
from utils import address_in_network
from form_of_sniffer import Form1
from scapy.all import *
import sys
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

        self.count_loopback_packets = 0
        self.count_capture_packets = 0
        self.count_multicast_packets = 0
        self.count_input_packets = 0
        #После каждого запуска снифера предыдущие данные будут очищаться
        self.text_zone.clear()

        'Вызов функция, запускающей сниффер'
        start_sniffer(interface=self.interface_of_capture)

        #Отображаем количество всех захваченных пакетов
        self.label_count_capture_packets.setText(f"{self.count_capture_packets}")
        #Отображаем количество захваченных пакетов loopback
        self.label_count_holentet_packets.setText(f"{self.count_loopback_packets}")
        # Отображаем количество захваченных пакетов broadcast
        self.label_count_multicast_packets.setText(f"{self.count_multicast_packets}")
        #Отображаем количество пакетов входящих в нашу сеть
        self.label_count_input_packets.setText(f"{self.count_input_packets}")
    def close_program(self):
        'Функция отвечающая за закрытие программы'
        self.close()



# Функция для обработки перехваченных пакетов
def packet_callback(packet):
    print(packet.summary())
    form.count_capture_packets+=1
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

#'Realtek RTL8822CE 802.11ac PCIe Adapter' - один из интерфейсов в Windows
#Функция запускающая сканирование и перехват пакетов(сниффинг)
def start_sniffer(interface):
    print("Запуск сниффера пакетов...")
    sniff(filter=f"net {form.network_of_capture}/24",iface=interface, prn=packet_callback, store=False,timeout=form.time_of_capture)



if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    form = Form_main()
    form.show()
    sys.exit(app.exec_())
