from PyQt5 import QtWidgets
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
        self.pushBatton_start_capture.clicked.connect(self.start_sniffing)
        self.pushBatton_finish_work.clicked.connect(self.close_program)

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
        #После каждого запуска снифера предыдущие данные будут очищаться
        self.text_zone.clear()
        'Вызов функция, запускающей сниффер'
        start_sniffer(interface=self.interface_of_capture)
    def close_program(self):
        'Функция отвечающая за закрытие программы'
        self.close()


# Функция для обработки перехваченных пакетов
def packet_callback(packet):
    print(packet.summary())

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

