#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/12/9 23:26
# @Author  : 周梦泽
# @File    : 南京信息工程大学海洋科学学院 - 海浪生成及观测虚拟仿真实验.py
# @Software: PyCharm
# 南京信息工程大学海洋科学学院 - 海浪生成及观测虚拟仿真实验模拟登录


import random
import ddddocr
import requests
from urllib import parse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
from fake_useragent import UserAgent

"""
key = 1234123412ABCDEF
mode = CBC
pad = PKCS7
"""


class NJULogin:
    def __init__(self, username: str, password: str):
        """
        :param username: 账号
        :param password: 密码
        """
        self.username = username
        self.password = password
        self.bast_url = "http://202.195.228.196"
        self.login_url = parse.urljoin(self.bast_url, 'index.php/Login/doLogin')
        # ?v=' + str(random.randrange(0, 10)) 这段生成随机数拼接去掉也可以的
        self.verify_url = parse.urljoin(self.bast_url, 'index.php/login/verify?v=' + str(random.randrange(0, 10)))
        self.headers = {'User-Agent': str(UserAgent().random),
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,'
                                  '*/*;q=0.8,application/signed-exchange;v=b3',
                        'Referer': 'http://202.195.228.196'
                        }
        self.sess = requests.Session()

    @staticmethod
    def encrypt(text: str) -> str:
        """
        进行AES加密
        加密原理：
        1.padding ：使用 PKCS7 填充
        2.mode ：CBC
        3.key ：1234123412ABCDEF
        4.IV：与key相同
        :param text:
        :return:
        """
        key = '1234123412ABCDEF'.encode('utf-8')
        text = text.encode('utf-8')
        # 使用 PKCS7 填充
        padded_data = pad(text, AES.block_size)
        # 创建 AES 密钥pip install pycryptodome
        cipher = AES.new(key, AES.MODE_CBC, key)
        # 加密
        ciphertext = cipher.encrypt(padded_data)
        return base64.b64encode(ciphertext).decode('utf-8')

    def identify_code(self) -> str:
        """
        识别验证码
        :return:
        """
        # 获取验证码图片
        code_img = self.sess.get(self.verify_url, headers=self.headers).content
        ocr = ddddocr.DdddOcr(beta=True, show_ad=False)
        code = ocr.classification(code_img)
        print(f"验证码为：{code}")
        return code

    def login(self):
        """模拟登录"""
        # 对密码进行加密
        code = self.identify_code()  # 识别验证码
        en_password = self.encrypt(self.password)
        # 登录
        login_data = {
            "username": self.username,
            "password": en_password,
            "verify_code": code
        }
        response = self.sess.post(self.login_url, headers=self.headers, data=login_data).json()
        print(response)


if __name__ == '__main__':
    nj = NJULogin(username="mason", password="Mz123456")
    nj.login()
