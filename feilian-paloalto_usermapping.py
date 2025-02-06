import os
import sys
import requests
import json
import base64
import socket
from datetime import datetime

# 尝试导入 Crypto，如果失败则自动安装 pycryptodome
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ModuleNotFoundError:
    print("检测到缺少 'pycryptodome' 库，正在安装...")
    os.system(f"{sys.executable} -m pip install pycryptodome")
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad

def encrypt_access_token(access_token):
    """使用 AES 加密 Access Token"""
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encrypted_bytes = cipher.encrypt(pad(access_token.encode(), AES.block_size))
    return base64.b64encode(encrypted_bytes).decode()


def decrypt_access_token(encrypted_token):
    """使用 AES 解密 Access Token"""
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    decrypted_bytes = unpad(cipher.decrypt(base64.b64decode(encrypted_token)), AES.block_size)
    return decrypted_bytes.decode()


def get_access_token(endpoint, access_key_id, access_key_secret):
    """获取 Access Token，并加密存储"""
    url = f"{endpoint}/api/open/v1/token"
    headers = {"Content-Type": "application/json;charset=utf-8"}
    body = {"access_key_id": access_key_id, "access_key_secret": access_key_secret}

    try:
        response = requests.post(url, headers=headers, json=body, verify=False)
        response_data = response.json()
        if response.status_code == 200 and "data" in response_data:
            access_token = response_data["data"].get("access_token")
            encrypted_token = encrypt_access_token(access_token)
            return encrypted_token
        else:
            print(f"获取 Access Token 失败: {response_data}")
            return None
    except requests.RequestException as e:
        print(f"请求错误: {e}")
        return None


def get_wifi_account_employees(endpoint, encrypted_access_token):
    """获取 WiFi 账户的员工列表信息"""
    decrypted_access_token = decrypt_access_token(encrypted_access_token)
    url = f"{endpoint}/api/open/v1/wifi/account/employee/list?connection_status=2"
    headers = {
        "Content-Type": "application/json;charset=utf-8",
        "Authorization": f"{decrypted_access_token}",
    }

    try:
        response = requests.get(url, headers=headers, verify=False)
        response_data = response.json()
        if response.status_code == 200 and "data" in response_data:
            return response_data["data"].get("items", [])
        else:
            print(f"获取 WiFi 账户信息失败: {response_data}")
            return []
    except requests.RequestException as e:
        print(f"请求错误: {e}")
        return []


def extract_account_ip(data):
    """解析账户和 IP 绑定关系"""
    account_ip_mapping = {}

    for entry in data:
        account = entry.get("account")
        connections = entry.get("connections", [])

        if connections:
            account_ip_mapping[account] = [conn.get("ip") for conn in connections if conn.get("ip")]

    return account_ip_mapping


def send_syslog_message(message):
    """发送 Syslog 消息到 Palo Alto 防火墙"""
    try:
        syslog_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        syslog_socket.sendto(message.encode(), (SYSLOG_SERVER, SYSLOG_PORT))
        syslog_socket.close()
        #print(f"Syslog 发送成功: {message}")
    except Exception as e:
        print(f"发送 Syslog 失败: {e}")


def send_account_ip_to_paloalto(account_ip_mapping):
    """将账户 IP 绑定信息通过 Syslog 发送到 Palo Alto 防火墙"""
    hostname = socket.gethostname()
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")  # Syslog 时间格式

    for account, ips in account_ip_mapping.items():
        for ip in ips:
            syslog_message = f"<{SYSLOG_FACILITY * 8 + 6}> {timestamp} {hostname} event_type=UserLogin UserID: {account} src_ip={ip} timeout={USERID_TIMEOUT}"
            send_syslog_message(syslog_message)
            print(f"已发送 Syslog: {syslog_message}")

# Palo Alto Syslog 服务器配置
SYSLOG_SERVER = "192.168.1.1"  # 替换为你的 Palo Alto 防火墙 IP 地址
SYSLOG_PORT = 514  # Palo Alto 默认 Syslog 端口
SYSLOG_FACILITY = 4  # 一般取 local4，对应 <134>（4*8+6）
USERID_TIMEOUT = 3600  # 超时时间 (秒)

# 确保 AES_KEY 是 16/24/32 字节，AES_IV 是 16 字节
AES_KEY = b"1234567890abcdef"  # 16字节密钥
AES_IV = b"abcdef1234567890"  # 16字节 IV

"""
param.endpoint            飞连Server
param.access_key_id       api_key-id
param.access_key_secret   api_key-secret
"""

endpoint = ""  #替换为你的 飞连 Server IP 地址
access_key_id = ""  #替换为你的 飞连 api key-id
access_key_secret = ""  #替换为你的 飞连 api key-secret

# === 调用示例 ===

# 获取加密的 Access Token
encrypted_access_token = get_access_token(endpoint, access_key_id, access_key_secret)
if not encrypted_access_token:
    print("未能成功获取 Access Token，程序终止。")
else:
    print("获取 Access Token 成功")

    # 获取 WiFi 账户的员工信息
    user_data = get_wifi_account_employees(endpoint, encrypted_access_token)

    if user_data:
        # 提取账户-IP 映射关系
        account_ip_mapping = extract_account_ip(user_data)

        # 发送数据到 Palo Alto 防火墙
        send_account_ip_to_paloalto(account_ip_mapping)
    else:
        print("未能获取 WiFi 账户员工信息。")
