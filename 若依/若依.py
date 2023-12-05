#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/12/5 11:03
# @Author  : 梦泽
# @File    : 若依.py.py
# @Software: PyCharm
import base64
from io import BytesIO
from urllib import parse
import requests
import pytesseract
from PIL import Image
from fake_useragent import UserAgent
import ddddocr


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
        self.headers = {'User-Agent': str(UserAgent().random),
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,'
                                  '*/*;q=0.8,application/signed-exchange;v=b3',
                        'Referer': self.bast_url}
        self.sess = requests.Session()

    def login(self):
        """模拟登录"""
        # 获取验证码
        code_url = parse.urljoin(self.bast_url, 'prod-api/captchaImage')
        code = self.sess.get(code_url, headers=self.headers).json()
        if code['msg'] == '操作成功':
            image_code = base64.b64decode(code['img'])  # 将验证码图片base64解码

            uuid = code['uuid']  # 获取uuid
            # 识别验证码1
            ocr = ddddocr.DdddOcr(show_ad=False)
            res = ocr.classification(image_code)
            print(f"验证码为：{res}")
            print(f"uuid为：{uuid}")
            image = Image.open(BytesIO(image_code))
            custom_config = r'--psm 6 -c tessedit_char_whitelist=0123456789-+=*/?'
            text = pytesseract.image_to_string(image, config=custom_config)
            print(f"ocr验证码为：{text}")
            # 显示图像
            image.show()

        # 识别验证码


if __name__ == '__main__':
    username = 'demo'
    password = 'quickon4You'
    zf = RYLogin(username, password)
    zf.login()
