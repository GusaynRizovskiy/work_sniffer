# -*- coding: utf-8 -*-
import socket
import struct
import ipaddress # <--- НОВОЕ: Импортируем модуль ipaddress
from scapy.all import get_if_list # Импортируем get_if_list из Scapy

def address_in_network(ip_address_str, network_cidr_str):
    """
    Эта функция позволяет проверить, принадлежит ли данный IP-адрес сетевой подсети.

    Пример: возвращает True, если ip = 192.168.1.1 и net = 192.168.1.0/24
             возвращает False, если ip = 192.168.1.1 и net = 192.168.100.0/24

    :param ip_address_str (str): IP-адрес для проверки (например, "192.168.1.5").
    :param network_cidr_str (str): Сеть в CIDR-нотации (например, "192.168.1.0/24").
    :rtype: bool
    """
    try:
        # Преобразуем строку IP-адреса в объект ip_address
        ip_addr = ipaddress.ip_address(ip_address_str)
        # Преобразуем строку CIDR в объект ip_network.
        # strict=False позволяет передавать IP-адрес хоста (например, "192.168.1.5/24"),
        # и он автоматически преобразуется в сетевой адрес (например, "192.168.1.0/24").
        network_obj = ipaddress.ip_network(network_cidr_str, strict=False)
        # Проверяем, находится ли IP-адрес внутри сети
        return ip_addr in network_obj
    except ValueError:
        # Если формат IP-адреса или сети некорректен, возвращаем False
        return False

def get_working_ifaces():
    """
    Возвращает список доступных сетевых интерфейсов с использованием Scapy.
    Это список объектов Scapy NetIFF.
    """
    return get_if_list()


__all__ = [
    'address_in_network',
    'get_working_ifaces' # Добавляем get_working_ifaces в __all__
]