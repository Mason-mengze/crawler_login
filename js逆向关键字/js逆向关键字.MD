## JS逆向中快速搜索定位加密函数技巧总结
### -内容来源
一、搜索加密函数常用关键词及说明：

1、 MD5：

搜索关键词：1732584193、271733879、1732584194、271733878、md5

原生MD5加密源码生成

2、SHA1：

搜索关键词：1732584193、271733879、1732584194、271733878、1009589776

SHA1源码加密源码生成

3、Base64：

ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 + /=

往往与其它加密函数结合使用

4、AES：

搜索关键词：crypto、AES、encrypt

往往与其它加密函数结合使用

5、DES：

搜索关键词：crypto、DES、encrypt、mode、padding

crypto官方网站

6、RSA：

搜索关键词：setPublicKey、rsa

jsencrypt官方网站

7、websocket：

搜索关键词：onopen、onmessage、onsent，WebSocket

协议ws和wss，类似http和https

8、JS编码：

搜索关键词：encodeURI、encodeURIComponent、btoa、escape

前面两种方式最为常见

9、加密函数导出：

搜索关键词：module.exports、exports

导出加密函数常用方法

10、FROM表单：

搜索关键词：password、pwd、sign、userid。加密或非加密，关键词，搜索词后面加冒号、等于号、前面加点，例如pwd:、pwd=、pwd =、.pwd

搜索表单键值对中值被加密的键，表单提交方式为POST，不同表单搜索关键词不同

11、十六进制：

搜索关键词：0123456789ABCDEF、0123456789abcdef

二、js逆向搜索加密函数要点：

1、判断加密的方式，一般在输入框中填写 123456 作为密码来判断，但表单加密的不一定是密码，还有可能是其它关键词

2、复杂的一点的网站，往往各咱加密方法混合使用

3、多研究各种加密源码，在下表中都已经提供加密源代码

4、加密的不一定只有密码，还有可能使用混淆技术，把加密的函数等给混淆，还有一些网站禁止使用浏览器调试工具

三、主要加密解密算法简介：：

1、对称性加密算法：对称式加密就是加密和解密使用同一个密钥（AES、DES、3DES）

2、非对称算法：非对称式加密就是加密和解密所使用的不是同一个密钥，通常有两个密钥，称为公钥、私钥，它们两个必需配对使用，否则不能打开加密文件（RSA、DSA、ECC）

3、散列算法：又称哈希函数，是一种单向加密算法，不可逆，目前无法解密（MD5、SHA1、HMAC）

4、Base64：算是一个编码算法，通常用于把二进制数据编码为可写的字符形式的数据，对数据内容进行编码来适合传输。这是一种可逆的编码方式。编码后的数据是一个字符串，其中包含的字符为：A - Z、a - z、0 - 9、+、/，共64个字符(26 + 26 + 10 + 1 + 1=64，其实是65个字符，“=”是填充字符（HTTPS、 HTTP + SSL层）

三、各种加密格式：

1、MD5常见16、32、40位

123456 加密（16位以49开头、32位e10或E10开头）:

`49BA59ABBE56E057`

`E10ADC3949BA59ABBE56E057F20F883E`

2、SHA1常见40、64、125位

123456 加密（40位以7c开头）:

`7c4a8d09ca3762af61e59520943dc26494f8941b`
3、HMAC
原始消息message，随机key，哈希算法，这里采用MD5，使用hmac的代码如下:

```
var message=b'Hello, world!'
# secret 密钥
var key=b'secret'
var h=hmac.new(key, message, digestmod='MD5')
# 如果消息很长，可以多次调用h.update(msg)
h.hexdigest()
```

4、AES
其中data 是字符串，若是对象则用JSON.stringify(data)转化:

```
var CryptoJS=require("crypto-js");
var data='my message';
# secret密钥
var secret='secret key 123';
// Encrypt
var ciphertext=CryptoJS.AES.encrypt(data, secret).toString();
// Decrypt
var bytes=CryptoJS.AES.decrypt(ciphertext, 'secret key 123');
var originalText=bytes.toString(CryptoJS.enc.Utf8);
```

4、DES

```
var CryptoJS=require("crypto-js");
const secretKey='com.sevenlin.foo.key';
var afterEncrypt=CryptoJS.DES.encrypt('passwordtoecrypt', CryptoJS.enc.Utf8.parse(secretKey), {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
}).toString()
# 解密
var afterDecrypt=CryptoJS.DES.decrypt(afterEncrypt, CryptoJS.enc.Utf8.parse(secretKey), {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
}).toString(CryptoJS.enc.Utf8);
```

5、RSA

```
# Encrypt with the public key...
var encrypt=new JSEncrypt();
# 公钥 public_key 加密
encrypt.setPublicKey(public_key);
var encrypted=encrypt.encrypt("加密内容");
# Decrypt with the private key...
var decrypt=new JSEncrypt();
# 私钥 private_key 解密
decrypt.setPrivateKey(private_key);
var uncrypted=decrypt.decrypt(encrypted);
```