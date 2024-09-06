#!/usr/bin/env python3
# vim: set fileencoding=utf-8

"""Implementations of wifi functions of Linux."""

import logging
import socket
import stat
import os
import re

from .const import *
from .profile import Profile

CTRL_IFACE_DIR = '/var/run/wpa_supplicant'
CTRL_IFACE_RETRY = 3
REPLY_SIZE = 4096

status_dict = {
    'completed': IFACE_CONNECTED,
    'inactive': IFACE_INACTIVE,
    'authenticating': IFACE_CONNECTING,
    'associating': IFACE_CONNECTING,
    'associated': IFACE_CONNECTING,
    '4way_handshake': IFACE_CONNECTING,
    'group_handshake': IFACE_CONNECTING,
    'interface_disabled': IFACE_INACTIVE,
    'disconnected': IFACE_DISCONNECTED,
    'scanning': IFACE_SCANNING
}

key_mgmt_to_str = {
    AKM_TYPE_WPA: 'WPA-EAP',
    AKM_TYPE_WPAPSK: 'WPA-PSK',
    AKM_TYPE_WPA2: 'WPA-EAP',
    AKM_TYPE_WPA2PSK: 'WPA-PSK',
    AKM_TYPE_WPA3: 'WPA-EAP-SHA256',
    AKM_TYPE_WPA3SAE: 'SAE',
    AKM_TYPE_WPA3ENT: 'WPA-EAP-SHA256',
}

key_mgmt_to_proto_str = {
    AKM_TYPE_WPA: 'WPA',
    AKM_TYPE_WPAPSK: 'WPA',
    AKM_TYPE_WPA2: 'RSN',
    AKM_TYPE_WPA2PSK: 'RSN',
    AKM_TYPE_WPA3: 'WPA3',
    AKM_TYPE_WPA3SAE: 'RSN',
    AKM_TYPE_WPA3ENT: 'WPA3',
}

display_str_to_key = {
    'open': AKM_TYPE_OPEN,
    'WPA': AKM_TYPE_WPA,
    'WPAPSK': AKM_TYPE_WPAPSK,
    'WPA2': AKM_TYPE_WPA2,
    'WPA2PSK': AKM_TYPE_WPA2PSK,
    'WPA3': AKM_TYPE_WPA3,
    'WPA3SAE': AKM_TYPE_WPA3SAE,
    'WPA3ENT': AKM_TYPE_WPA3ENT,
}

proto_to_key_mgmt_id = {
    'WPA': AKM_TYPE_WPAPSK,
    'RSN': AKM_TYPE_WPA2PSK,
}

cipher_str_to_value = {
    'TKIP': CIPHER_TYPE_TKIP,
    'CCMP': CIPHER_TYPE_CCMP,
}

class WifiUtil():
    """WifiUtil implements the wifi functions in Linux."""

    _connections = {}
    _logger = logging.getLogger('pywifi')

    def scan(self, obj):
        """Trigger the wifi interface to scan."""

        self._send_cmd_to_wpas(obj['name'], 'SCAN')

    def scan_results(self, obj):
        """Get the AP list after scanning."""

        bsses = []
        bsses_summary = self._send_cmd_to_wpas(obj['name'], 'SCAN_RESULTS', True)
        bsses_summary = bsses_summary[:-1].split('\n')
        if len(bsses_summary) == 1:
            return bsses

        for l in bsses_summary[1:]:
            values = l.split('\t')
            bss = Profile()
            bss.bssid = values[0]
            bss.freq = int(values[1])
            bss.signal = int(values[2])

            # 定义一个正则表达式来匹配ssid转义序列
            pattern = r'\\x([0-9a-fA-F]{2}|[0-9a-fA-F]{4})'
            # 使用lambda表达式来替换匹配到的ssid转义序列
            ssid = re.sub(pattern, lambda m: chr(int(m.group(1), 16)), values[4])

            # * 该部分用于将SSID转换为UTF-8编码，可正常显示中文字符 p.s.由 PR #31 提供
            temp_cnt = 0
            temp_hex_res = 0
            bytes_list = []
            converted_name = ""
            for bin_encode_char in ssid:
                if (32 <= ord(bin_encode_char) <= 126):
                    converted_name += bin_encode_char
                else:
                    temp_cnt += 1
                    temp_now = int(str(bin(ord(bin_encode_char)))[2:6], 2)
                    temp_now1 = int(str(bin(ord(bin_encode_char)))[6:10], 2)
                    temp_hex_res = temp_hex_res + temp_now * 16 + temp_now1
                    bytes_list.append(temp_hex_res)
                    temp_hex_res = 0
                    # 收集到完整的UTF-8字符时（最多四个字节）
                    if temp_cnt >= 1 and temp_cnt <= 4:
                        try:
                            converted_name = converted_name + bytes(bytes_list).decode('utf-8')
                            bytes_list = []
                            temp_hex_res = 0
                            temp_cnt = 0
                        except UnicodeDecodeError:
                            # 如果解码失败，忽略错误并继续处理下一个字符
                            pass
            # 处理末尾可能剩下的未完成的字节序列
            if bytes_list:
                try:
                    decoded_chars = bytes(bytes_list).decode('utf-8', 'ignore')
                    converted_name += decoded_chars
                except UnicodeDecodeError:
                    pass
            bss.ssid = converted_name

            bss.akm = 7
            if 'WPA-PSK' in values[3]:
                bss.akm = AKM_TYPE_WPAPSK
            elif 'WPA2-PSK' in values[3]:
                bss.akm = AKM_TYPE_WPA2PSK
            elif 'WPA2-SAE' in values[3]:
                bss.akm = AKM_TYPE_WPA3SAE
            elif 'WPA-EAP' in values[3]:
                bss.akm = AKM_TYPE_WPA
            elif 'WPA2-EAP' in values[3]:
                bss.akm = AKM_TYPE_WPA2

            bss.auth = AUTH_ALG_OPEN

            bsses.append(bss)

        return bsses

    def connect(self, obj, network):
        """Connect to the specified AP."""

        network_summary = self._send_cmd_to_wpas(
            obj['name'],
            'LIST_NETWORKS',
            True)
        network_summary = network_summary[:-1].split('\n')
        if len(network_summary) == 1:
            return networks

        for l in network_summary[1:]:
            values = l.split('\t')
            if values[1] == network.ssid:
                network_summary = self._send_cmd_to_wpas(
                    obj['name'],
                    'SELECT_NETWORK {}'.format(values[0]),
                    True)

    def disconnect(self, obj):
        """Disconnect to the specified AP."""

        self._send_cmd_to_wpas(obj['name'], 'DISCONNECT')

    def add_network_profile(self, obj, params):
        """Add an AP profile for connecting to afterward."""

        network_id = self._send_cmd_to_wpas(obj['name'], 'ADD_NETWORK', True)
        network_id = network_id.strip()

        # params.process_akm()

        self._send_cmd_to_wpas(
                obj['name'],
                'SET_NETWORK {} ssid \"{}\"'.format(network_id, params.ssid))

        key_mgmt = ''
        # if params.akm in [AKM_TYPE_WPAPSK, AKM_TYPE_WPA2PSK]:
        #     key_mgmt = 'WPA-PSK'
        # elif params.akm in [AKM_TYPE_WPA, AKM_TYPE_WPA2]:
        #     key_mgmt = 'WPA-EAP'
        # else:
        #     key_mgmt = 'NONE'
        if params.akm in key_mgmt_to_str:
            key_mgmt = key_mgmt_to_str[params.akm]
        else:
            key_mgmt = 'NONE'

        if key_mgmt:
            self._send_cmd_to_wpas(
                    obj['name'],
                    'SET_NETWORK {} key_mgmt {}'.format(
                        network_id,
                        key_mgmt))

        proto = ''
        # if params.akm in [AKM_TYPE_WPAPSK, AKM_TYPE_WPA]:
        #     proto = 'WPA'
        # elif params.akm in [AKM_TYPE_WPA2PSK, AKM_TYPE_WPA2]:
        #     proto = 'RSN'
        if params.akm in key_mgmt_to_proto_str:
            proto = key_mgmt_to_proto_str[params.akm]
        else:
            proto = 'RSN'

        if proto:
            self._send_cmd_to_wpas(
                    obj['name'],
                    'SET_NETWORK {} proto {}'.format(
                        network_id,
                        proto))

        if params.akm in key_mgmt_to_str:
            self._send_cmd_to_wpas(
                    obj['name'],
                    'SET_NETWORK {} psk \"{}\"'.format(network_id, params.key))

        return params

    def network_profiles(self, obj):
        """Get AP profiles."""

        networks = []
        network_ids = []
        network_summary = self._send_cmd_to_wpas(
            obj['name'],
            'LIST_NETWORKS',
            True)
        network_summary = network_summary[:-1].split('\n')
        if len(network_summary) == 1:
            return networks

        for l in network_summary[1:]:
            network_ids.append(l.split()[0])

        for network_id in network_ids:
            network = Profile()

            network.id = network_id

            ssid = self._send_cmd_to_wpas(
                obj['name'],
                'GET_NETWORK {} ssid'.format(network_id), True)
            if ssid.upper().startswith('FAIL'):
                continue
            else:
                network.ssid = ssid[1:-1]

            key_mgmt = self._send_cmd_to_wpas(
                obj['name'],
                'GET_NETWORK {} key_mgmt'.format(network_id),
                True)

            network.akm = []
            if key_mgmt.upper().startswith('FAIL'):
                continue
            else:
                if key_mgmt.upper() == 'WPA-PSK':
                    proto = self._send_cmd_to_wpas(
                        obj['name'],
                        'GET_NETWORK {} proto'.format(network_id),
                        True)

                    if proto.upper() == 'RSN':
                        network.akm = AKM_TYPE_WPA2PSK
                    else:
                        network.akm = AKM_TYPE_WPAPSK
                elif key_mgmt.upper() == 'SAE' or key_mgmt.upper() == "WPA-EAP-SHA256":
                    proto = self._send_cmd_to_wpas(
                        obj['name'],
                        'GET_NETWORK {} proto'.format(network_id),
                        True)

                    if proto.upper() == 'RSN':
                        network.akm = AKM_TYPE_WPA3SAE
                    else:
                        network.akm = AKM_TYPE_WPA3
                elif key_mgmt.upper() == 'WPA-EAP':
                    proto = self._send_cmd_to_wpas(
                        obj['name'],
                        'GET_NETWORK {} proto'.format(network_id),
                        True)

                    if proto.upper() == 'RSN':
                        network.akm = AKM_TYPE_WPA2
                    else:
                        network.akm = AKM_TYPE_WPA

            ciphers = self._send_cmd_to_wpas(
                obj['name'],
                'GET_NETWORK {} pairwise'.format(network_id),
                True).split(' ')

            if ciphers[0].upper().startswith('FAIL'):
                continue
            else:
                # Assume the possible ciphers TKIP and CCMP
                if len(ciphers) == 1:
                    network.cipher = cipher_str_to_value(ciphers[0].upper())
                elif 'CCMP' in ciphers:
                    network.cipher = CIPHER_TYPE_CCMP

            networks.append(network)

        return networks

    def remove_network_profile(self, obj, params):
        """Remove the specified AP profiles"""

        network_id = -1
        profiles = self.network_profiles(obj)

        for profile in profiles:
            if profile == params:
                network_id = profile.id

        if network_id != -1:
            self._send_cmd_to_wpas(obj['name'],
                'REMOVE_NETWORK {}'.format(network_id))

    def remove_all_network_profiles(self, obj):
        """Remove all the AP profiles."""

        self._send_cmd_to_wpas(obj['name'], 'REMOVE_NETWORK all')

    def status(self, obj):
        """Get the wifi interface status."""

        reply = self._send_cmd_to_wpas(obj['name'], 'STATUS', True)
        result = reply.split('\n')

        status = ''
        for l in result:
            if l.startswith('wpa_state='):
                status = l[10:]
                return status_dict[status.lower()]

    def interfaces(self):
        """Get the wifi interface lists."""
        
        ifaces = []
        for f in sorted(os.listdir(CTRL_IFACE_DIR)):
            sock_file = '/'.join([CTRL_IFACE_DIR, f])
            mode = os.stat(sock_file).st_mode
            if stat.S_ISSOCK(mode):
                iface = {}
                iface['name'] = f
                ifaces.append(iface)
                self._connect_to_wpa_s(f)

        return ifaces

    def _connect_to_wpa_s(self, iface):

        ctrl_iface = '/'.join([CTRL_IFACE_DIR, iface])
        if ctrl_iface in self._connections:
            self._logger.info(
                "Connection for iface '%s' aleady existed!",
                iface)

        sock_file = '{}/{}_{}'.format('/tmp', 'pywifi', iface)
        self._remove_existed_sock(sock_file)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(sock_file)
        sock.connect(ctrl_iface)

        send_len = sock.send(b'PING')
        retry = CTRL_IFACE_RETRY
        while retry >= 0:
            reply = sock.recv(REPLY_SIZE)
            if reply == b'':
                self._logger.error("Connection to '%s' is broken!", iface_ctrl)
                break

            if reply.startswith(b'PONG'):
                self._logger.info(
                    "Connect to sock '%s' successfully!", ctrl_iface)
                self._connections[iface] = {
                    'sock': sock,
                    'sock_file': sock_file,
                    'ctrl_iface': ctrl_iface
                }
                break
            retry -= 1

    def _remove_existed_sock(self, sock_file):

        if os.path.exists(sock_file):
            mode = os.stat(sock_file).st_mode
            if stat.S_ISSOCK(mode):
                os.remove(sock_file)

    def _send_cmd_to_wpas(self, iface, cmd, get_reply=False):

        if 'psk' not in cmd:
            self._logger.info("Send cmd '%s' to wpa_s", cmd)
        sock = self._connections[iface]['sock']

        sock.send(bytearray(cmd, 'utf-8'))
        reply = sock.recv(REPLY_SIZE)
        if get_reply:
            return reply.decode('utf-8')

        if reply != b'OK\n':
            self._logger.error(
                "Unexpected resp '%s' for Command '%s'",
                reply.decode('utf-8'),
                cmd)
