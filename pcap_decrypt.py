# -*-coding=utf-8 -*-

"""
用于分析小米网关流量

需要的参数：
：params token：网关主密钥 MK
：params path：网关通信流量 pcap 文件路径
"""

import hashlib
import re

from Crypto.Cipher import AES
import scapy.all as scapy


def pkcs7padding(text):
    """
    明文使用PKCS7填充
    最终调用AES加密方法时，传入的是一个byte数组，要求是16的整数倍，因此需要对明文进行处理
    :param text: 待加密内容(明文)
    :return: 待加密内容(明文+填充)
    """
    bs = AES.block_size  # 16
    length = len(text)
    bytes_length = len(bytes(text, encoding='utf-8'))
    # tips：utf-8编码时，英文占1个byte，而中文占3个byte
    padding_size = length if(bytes_length == length) else bytes_length
    padding = bs - padding_size % bs
    # tips：chr(padding)看与其它语言的约定，有的会使用'\0'
    padding_text = chr(padding) * padding
    return text + padding_text


def pkcs7unpadding(text):
    """
    处理使用PKCS7填充过的数据
    :param text: 解密后的字符串
    :return: 去掉填充的明文串
    """
    length = len(text)
    unpadding = ord(text[length-1])
    return text[0:length-unpadding]


def encrypt(key, iv, content):
    """
    AES加密（cbc模式，pkcs#7填充）

    :param key: 密钥
    :param iv: 加密初始向量
    :param content: 加密内容（明文）
    :return: 密文内容
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # 处理明文
    content_padding = pkcs7padding(content)
    # 加密
    encrypt_bytes = cipher.encrypt(bytes(content_padding, encoding='utf-8'))
    return encrypt_bytes


def decrypt(key, iv, content):
    """
    AES解密（cbc模式，pkcs#7填充）

    :param key: 密钥
    :param iv: 加密初始向量
    :param content: 解密内容（密文）
    :return: 明文内容
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # 解密
    decrypt_bytes = cipher.decrypt(content)
    # 重新编码
    result = str(decrypt_bytes, encoding='utf-8')
    # 去除填充内容
    result = pkcs7unpadding(result)
    return result


def get_key(token):
    """
    计算密钥

    :param token: 加密凭据
    :return: 密钥
    """
    hash_val = hashlib.md5(token)
    key = bytes.fromhex(hash_val.hexdigest())
    return key


def get_iv(token, key):
    """
    计算初始向量

    :param token: 加密凭据
    :param key: 密钥
    :return:
    """
    hash_val = hashlib.md5(key+token)
    iv = bytes.fromhex(hash_val.hexdigest())
    return iv


def anylase_mob_udp(path):
    """
    解析通过tcpdump抓到的udp数据包(含有握手包的手机通信流量)

    :param path: pcap文件路径
    :return: 明文消息列表
    """
    # 加密参数
    token = None
    key = None
    iv = None
    # 解密出的明文列表
    messages = []
    # 读取数据包，并解密
    pcap = scapy.rdpcap(path)
    for packet in pcap:
        if packet.haslayer("UDP") and (packet["UDP"].sport == 54321 or packet["UDP"].dport == 54321):
            src_ip = packet["IP"].src  # 源地址
            dst_ip = packet["IP"].dst  # 目的地址
            if packet["UDP"].sport != 54321:  # 数据包方向
                direction = "send"
            else:
                direction = "recv"
            payload = packet["UDP"].payload.load  # 消息载荷
            # 过滤掉broadcast包
            if packet["Ethernet"].dst == "ff:ff:ff:ff:ff:ff":
                continue
            # 配网过程中发送token的握手包
            if token is None and src_ip.split(".")[-1] == "1":
                # 获取到token
                token = payload[16:]
                # 计算key和iv
                key = get_key(token)
                iv = get_iv(token, key)
            # 解密消息
            if len(payload) > 32:
                assert(token is not None)
                cipher = payload[32:]
                plain = decrypt(key, iv, cipher)
                id_search = re.search(r"\"id\":(\d+)", plain)
                if id_search is None:
                    gw_id = None
                else:
                    gw_id = id_search.group(1)
                messages.append({"src": src_ip, "dst": dst_ip, "dir": direction, "id": gw_id, "msg": plain})
    # 测试流量中单个数据包的解密
    # data = bytes.fromhex("2131008000000000059ea2cb000000ac38e742e1d35310730b418f9f19254f23de7aab8c309a6d46ec71bffd1e0987368aaa05d1485980f36d52809230620b86bd996e01dac689e4452aaa3cf1c0b3e3378dfe7b87d5ae6c2d75690e2d9fdd720ddb6a784abd20ba35eef8f2a5b080df4431f2262e17a3a23b019ee7ae6ab2c0")
    # m = decrypt(key, iv, data[32:])
    # print(m)
    return messages


def anylase_gw_udp(path, token):
    """
    解析通过wireshark抓到的udp数据包(电脑AP抓获到的网关流量)

    :param path: pcap文件路径
    :return: 明文消息列表
    """
    # 计算key和iv
    key = get_key(token)
    iv = get_iv(token, key)
    # 解密出的明文列表
    messages = []
    # 读取数据包，并解密
    pcap = scapy.rdpcap(path)
    for packet in pcap:
        if packet.haslayer("UDP") and (packet["UDP"].sport == 54321 or packet["UDP"].dport == 54321):
            src_ip = packet["IP"].src  # 源地址
            dst_ip = packet["IP"].dst  # 目的地址
            if packet["UDP"].sport == 54321:  # 数据包方向
                direction = "send"
            else:
                direction = "recv"
            payload = packet["UDP"].payload.load  # 消息载荷
            # 过滤掉broadcast包
            if packet["Ethernet"].dst == "ff:ff:ff:ff:ff:ff":
                continue
            # 解密消息
            if len(payload) > 32:
                assert (token is not None)
                cipher = payload[32:]
                plain = decrypt(key, iv, cipher)
                id_search = re.search(r"\"id\":(\d+)", plain)
                if id_search is None:
                    gw_id = None
                else:
                    gw_id = id_search.group(1)
                messages.append({"src": src_ip, "dst": dst_ip, "dir": direction, "id": gw_id, "msg": plain})
    # 测试流量中单个数据包的解密
    # data = bytes.fromhex("2131007000000000059ea2cb5db58f6c00fafe7169916cafccfedfa3e7986cd4813ac8a636b4d0dbe8a9f1ae762ba6c57daa56962474c8ed6c560d56bd1c2ecbf8ed9c876b69d10bf7f63387f04eeaab244d9e21a6aa76a65437ae2f3f340b513cb3989917a46c72f485ac5a41832858")
    # m = decrypt(key, iv, data[32:])
    # print(m)
    return messages


def show_msg(msg_list):
    """
    展示消息列表

    :param msg_list: 明文消息列表
    :return: 
    """
    for msg in msg_list:
        # 发送/接收的箭头方向
        direct = ""
        if msg["dir"] == "send":
            direct += "  ==>  "
        else:
            direct += "  <==  "
        # 源/目的IP的说明
        if msg["src"].rsplit(".", 1)[0] == msg["dst"].rsplit(".", 1)[0]:
            print("\n" + msg["src"] + "（手机） <===> " + msg["dst"] + "（网关）")
        else:
            print("\n" + msg["src"] + "（网关） <===> " + msg["dst"] + "（服务器）")
        print("\t"+msg["msg"])


if __name__=="__main__":
    print("============ 手机与网关的流量分析 ===============")
    mob_msgs = anylase_mob_udp("20191030-mob-lan-then-wan.pcap")
    show_msg(mob_msgs)

    print("============ 网关与服务器的流量分析 ===============")
    # 网关189e的MasterKey
    tok = bytes.fromhex("4E5348624A6368356F32454334567633")
    gw_msgs = anylase_gw_udp("20191030-com-lan-then-wan.pcapng", tok)
    show_msg(gw_msgs)
