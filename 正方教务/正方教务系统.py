from urllib import parse
import requests
from bs4 import BeautifulSoup
import rsa
import binascii
from fake_useragent import UserAgent
import ddddocr


class ZfLogin:
    def __init__(self, username: str, password: str):
        """
        :param username: 学号
        :param password: 密码
        """
        self.username = username
        self.password = password
        self.bast_url = "https://jwxt.gcc.edu.cn"  # 根据自己学校的教务系统进行修改
        self.key_url = parse.urljoin(self.bast_url, '/xtgl/login_getPublicKey.html')
        self.login_url = parse.urljoin(self.bast_url, '/xtgl/login_slogin.html')
        self.code_url = parse.urljoin(self.bast_url, '/kaptcha')
        self.headers = {'User-Agent': str(UserAgent().random),
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,'
                                  '*/*;q=0.8,application/signed-exchange;v=b3',
                        'Referer': self.login_url}
        self.sess = requests.Session()

    def login(self):
        """模拟登录"""
        req = self.sess.get(self.login_url, headers=self.headers)
        soup = BeautifulSoup(req.text, 'lxml')
        tokens = soup.find(id='csrftoken').get("value")
        # 获取公钥
        response_data = self.sess.get(self.key_url, headers=self.headers).json()
        modulus = response_data["modulus"]
        exponent = response_data["exponent"]

        # 获取验证码
        code = self.sess.get(self.code_url, headers=self.headers).content
        ocr = ddddocr.DdddOcr(beta=True, show_ad=False)
        res = ocr.classification(code)
        print(f"验证码为：{res}")
        # 对密码进行加密
        en_password = self.get_rsa(self.password, modulus, exponent)
        # 登录
        login_data = {
            "csrftoken": tokens,  # 实际测试csrftoken不传也没问题，但是为了防止以后出现问题，还是加上吧
            "yhm": self.username,
            "mm": en_password,
            'mm': en_password,
            'yzm': res
        }
        response = self.sess.post(self.login_url, headers=self.headers, data=login_data)
        print(response.text)
        return response

    @staticmethod
    def get_rsa(pwd: str, n: str, e: str):
        """
        对密码进行rsa加密
        :param pwd: 密码
        :param n:  RSA 公钥的模数
        :param e: RSA 公钥的指数
        """

        message = str(pwd).encode()
        rsa_n = binascii.b2a_hex(binascii.a2b_base64(n))
        rsa_e = binascii.b2a_hex(binascii.a2b_base64(e))
        key = rsa.PublicKey(int(rsa_n, 16), int(rsa_e, 16))
        encropy_pwd = rsa.encrypt(message, key)
        result = binascii.b2a_base64(encropy_pwd)
        return result


if __name__ == '__main__':
    username = input("请输入学号：")
    password = input("请输入密码：")
    zf = ZfLogin(username, password)
    zf.login()
