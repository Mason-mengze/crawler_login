#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/12/4 14:33
# @Author  : 梦泽
# @File    : ATExpert.py
# @Software: PyCharm
# 公司内网ATE程序管理系统模拟登录

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
from fake_useragent import UserAgent


def encrypt(text: str, key: str = "awptech_atexpert") -> str:
    """
    进行AES加密
    加密原理：
    1.padding ：使用 PKCS7 填充
    2.mode ：ECB
    3.key ：awptech_atexpert
    4.IV：使用自动生成 默认不填
    :param text:需要加密的文本
    :param key:加密的key
    :return:
    """
    key = key.encode('utf-8')
    text = text.encode('utf-8')
    # 使用 PKCS7 填充
    padded_data = pad(text, AES.block_size)
    # 创建 AES 密钥pip install pycryptodome
    cipher = AES.new(key, AES.MODE_ECB)
    # 加密
    ciphertext = cipher.encrypt(padded_data)
    # 返回 Base64 编码的密文
    return base64.b64encode(ciphertext).decode('utf-8')


headers = {
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Origin': 'http://192.168.2.175',
    'Pragma': 'no-cache',
    'Referer': 'http://192.168.2.175/login',
    'User-Agent': str(UserAgent().random),
    'dnt': '1',
    'sec-gpc': '1',
}
# 账号密码
text = '{"username":"xxxx","password":"xxxxxxxx","code":""}'
json_data = encrypt(text)

response = requests.post('http://192.168.2.175/api/auth/login', headers=headers, json=json_data, verify=False).json()
print(response)
