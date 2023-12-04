#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/12/4 15:14
# @Author  : 梦泽
# @File    : 禅道.py
# @Software: PyCharm
# 禅道逆向模拟登录
import time
from urllib import parse
import requests
from fake_useragent import UserAgent
from hashlib import md5

class ZentaoLogin:
    def __init__(self, username: str, password: str):
        """
        :param username: 用户名
        :param password: 密码
        """
        self.username = username
        self.password = password
        self.bast_url = "https://zentao.demo.qucheng.cc"  # 我这里是公司内网地址，根据自己的进行修改
        self.headers = {'User-Agent': str(UserAgent().random),
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,'
                                  '*/*;q=0.8,application/signed-exchange;v=b3',
                        'Referer': parse.urljoin(self.bast_url, '/user-login.html')}
        self.sess = requests.Session()

    def login(self):
        """
        模拟登录
        加密原理：1.发送请求向后端获取随机码
                2.对密码进行第一次加密
                3.对第一次加密后的密码和随机码进行第二次加密
        """
        random_code = self.sess.get(parse.urljoin(self.bast_url, '/user-refreshRandom.html'),
                                    headers=self.headers).text
        print(random_code)
        # 网站使用了双层MD5加密，第一层是对密码进行MD5加密，第二层是对第一层加密后的密码和随机码进行MD5加密
        en_password = md5((md5(password.encode('utf-8')).hexdigest() + random_code).encode('utf-8')).hexdigest()
        print(en_password)
        login_data = {
            "account": self.username,
            "password": en_password,
            'passwordStrength': 0,
            'referer': '/',
            'verifyRand': random_code,
            'keepLogin': 0,
            'captcha': ''
        }
        response = self.sess.post(parse.urljoin(self.bast_url, '/user-login.html'), headers=self.headers,
                                  data=login_data)
        print(response.text)    # 查看登陆后的页面


if __name__ == '__main__':
    username = 'demo'
    password = 'quickon4You'
    zf = ZentaoLogin(username, password)
    zf.login()
