import socket
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import hashlib
import binascii

def get_cipher_message(message):
    cipherMessage = message[32:]
    return str(binascii.b2a_hex(cipherMessage))[2:-1]

def get_key(token):
    m = hashlib.md5()
    m.update(token)  #key = md5(token)
    key = m.digest()
    return key

def get_iv(token,key):
    m = hashlib.md5()
    m.update(key+token)  #iv = md5(md5(token)+token)
    iv = m.digest()
    return iv

# 如果text不足16位的倍数就用空格补足为16位
def add_to_16(text):
    if len(text.encode('utf-8')) % 16:
        add = 16 - (len(text.encode('utf-8')) % 16)
    else:
        add = 0
    text = text + (chr(add) * add)
    return text.encode('utf-8')

# 加密函数
def encrypt(text,key,iv):
    mode = AES.MODE_CBC
    text = add_to_16(text)
    cryptos = AES.new(key, mode, iv)
    cipher_text = cryptos.encrypt(text)
    # 因为AES加密后的字符串不一定是ascii字符集的，输出保存可能存在问题，所以这里转为16进制字符串
    return b2a_hex(cipher_text)

# 解密后，去掉补足的空格用strip() 去掉
def decrypt(text,key,iv):
    mode = AES.MODE_CBC
    cryptos = AES.new(key, mode, iv)
    plain_text = cryptos.decrypt(a2b_hex(text))
#    print(b2a_hex(plain_text))
    return bytes.decode(plain_text).rstrip('\0')

def send_message(MESSAGE,UDP_IP, UDP_PORT):
    sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))

def receive_message(UDP_IP, UDP_PORT):
    sock.connect((UDP_IP, UDP_PORT))
    flag = 1
    while flag:
        data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
        print("received message:", data)
        flag = 0
    return data#str(binascii.b2a_hex(data))[2:-1]


if __name__ == '__main__':
    UDP_IP = "192.168.43.227"
    UDP_PORT = 54321
    HELLO_MESSAGE = b'!1\x00 \xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP

# send hello packet and get token
    send_message(HELLO_MESSAGE,UDP_IP, UDP_PORT)
    token_message_data = receive_message(UDP_IP, UDP_PORT)
    token_message = str(binascii.b2a_hex(token_message_data))[2:-1]

###using old pcap data to test function
    token = b'\xc1`C\x00\x8d\xcc"\x9e\xe4\x1c\xc4\xa5\xf8\xde\xb5\x84'

# prepare for the encryption
    key = get_key(token)
    iv = get_iv(token,key)

# replay packet generation

    # wifi information message
    wifi_message = '{"id":65010,"method":"set_night_light_rgb","params":[1226899711]}'
    wifi_ciphertext = encrypt(wifi_message,key,iv).decode("ascii")
    length = len(wifi_ciphertext)
    print(length)

    # head information message
    message_length = hex(int(length/2)+32)


    packet_head_message = token_message[:6]+message_length[2:]+token_message[8:]
    print(packet_head_message)

    # checksum generation
    checksum_text = bytes.fromhex(packet_head_message+wifi_ciphertext)
    print(str(binascii.b2a_hex(token))[2:-1],'token')
    print(str(binascii.b2a_hex(checksum_text))[2:-1])

    checksum = hashlib.md5()
    checksum.update(checksum_text)
    print(checksum.hexdigest(),'checksum')

    # packet construction
    packet_final = packet_head_message[:32]+checksum.hexdigest()+wifi_ciphertext
    print(packet_final)

# sending message to Iot
    wifi_packet_data = bytes().fromhex(packet_final)
    send_message(wifi_packet_data,UDP_IP,UDP_PORT)
    wifi_reply=receive_message(UDP_IP, UDP_PORT)
    wifi_reply_ciphertext = get_cipher_message(wifi_reply)
    d = decrypt(wifi_reply_ciphertext,key,iv)
    print("After dencrypting:", d)
    print('connecting successfully! hiahia')
    #print(packet_head_message+bytes().fromhex(checksum.hexdigest())+wifi_ciphertext)