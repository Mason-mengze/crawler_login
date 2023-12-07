#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/12/5 11:03
# @Author  : 梦泽
# @File    : 若依.py.py
# @Software: PyCharm
import base64
import json
from urllib import parse
import requests
from fake_useragent import UserAgent


class RYLogin:
    def __init__(self, username: str, password: str):
        """
        :param username: 账号
        :param password: 密码
        """
        self.username = username
        self.password = password
        self.bast_url = "http://vue.ruoyi.vip"  # 若依演示demo  前端分离版
        self.login_url = parse.urljoin(self.bast_url, 'prod-api/login')
        self.index_url = parse.urljoin(self.bast_url, 'index')
        self.headers = {'User-Agent': str(UserAgent().random),
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,'
                                  '*/*;q=0.8,application/signed-exchange;v=b3',
                        'Content-Type': 'application/json;charset=UTF-8',
                        'Referer': 'http://vue.ruoyi.vip/login?redirect=%2Findex'
                        }
        self.sess = requests.Session()

    def login(self, code_api_username, code_api_password):
        """模拟登录"""
        # 获取验证码
        code_url = parse.urljoin(self.bast_url, 'prod-api/captchaImage')
        code = self.sess.get(code_url, headers=self.headers).json()
        if code['msg'] == '操作成功':
            image_code = base64.b64decode(code['img'])  # 将验证码图片base64解码

            uuid = code['uuid']  # 获取uuid
            print(f"uuid为：{uuid}")
            # 识别验证码
            code = self.get_code_text(code['img'], 120103, code_api_username, code_api_password)
            print(f"验证码为：{code}")
            data = {
                "code": code,
                "username": self.username,
                "password": self.password,
                "uuid": uuid
            }
            if int(data['code']) != 0:
                print("验证码识别错误")
                raise Exception("验证码识别错误")
            response = self.sess.post(self.login_url, headers=self.headers, data=json.dumps(data)).json()
            if response['msg'] != '操作成功':
                print('登陆失败')
                print(response['msg'])
                raise Exception("登陆失败")
            print('登陆成功')

    @staticmethod
    def get_code_text(img_64: str, code_type: int, code_api_username: str, code_api_password: str):
        """
        识别验证码
        :return:
        """
        api_post_url = "http://www.bingtop.com/ocr/upload/"  # 打码平台接口地址
        params = {
            "username": code_api_username,
            "password": code_api_password,
            "captchaData": img_64,  # 验证码图片base64编码
            "captchaType": code_type  # 验证码类型
        }
        response = requests.post(api_post_url, data=params).json()
        print(response)
        dictdata = response['data']['recognition']
        return dictdata


if __name__ == '__main__':
    username = 'admin'
    password = 'admin123'
    code_api_username = 'mason1'  # 打码平台账号 可无限注册
    code_api_password = 'mz1258012581'
    zf = RYLogin(username, password)
    zf.login(code_api_username, code_api_password)
