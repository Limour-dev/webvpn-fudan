from aes_cfb import getCiphertext, getPlaintext
from binascii import hexlify, unhexlify

key_ = b'wrdvpnisthebest!'
iv_  = b'wrdvpnisthebest!'
institution = 'webvpn.fudan.edu.cn'

def getVPNUrl(url):
    '''From ordinary url to webVPN url'''

    parts = url.split('://')
    pro = parts[0]
    add = parts[1]
    
    hosts = add.split('/')
    cph = getCiphertext(hosts[0], key=key_, cfb_iv=iv_)
    fold = '/'.join(hosts[1:])

    key = hexlify(iv_).decode('utf-8')
    
    return 'https://' + institution + '/' + pro + '/' + key + cph + '/' + fold

def getOrdinaryUrl(url):
    '''From webVPN url to ordinary url'''

    parts = url.split('/')
    pro = parts[3]
    key_cph = parts[4]
    
    if key_cph[:16] == hexlify(iv_).decode('utf-8'):
        print(key_cph[:32])
        return None
    else:
        hostname = getPlaintext(key_cph[32:], key=key_, cfb_iv=iv_)
        fold = '/'.join(parts[5:])

        return pro + "://" + hostname + '/' + fold

from lxml import etree
from requests import session

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class WebVPN:
    UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0"
    def __init__(self, uid, psw):
        self.session = session()
        self.session.verify = False
        self.url_login = 'https://webvpn.fudan.edu.cn/https/77726476706e69737468656265737421e5fe52d221256c5170468ca88d1b203b/authserver/login?service=https://webvpn.fudan.edu.cn/login?cas_login=true'
        self.uid = uid
        self.psw = psw

    def login(self):
        page_login = self.session.get(self.url_login).text
        html = etree.HTML(page_login, etree.HTMLParser())
        data = {
            "username": self.uid,
            "password": self.psw,
        }
        # 获取登录页上的令牌
        data.update(
                zip(
                        html.xpath("/html/body/form/input/@name"),
                        html.xpath("/html/body/form/input/@value")
                )
        )
        headers = {
            "Origin"    : 'webvpn.fudan.edu.cn',
            "Referer"   : self.url_login,
            "User-Agent": self.UA
        }
        post = self.session.post(
                self.url_login,
                data=data,
                headers=headers,
                allow_redirects=True)        
        return self.session.cookies.get_dict()

    def logout(self):
        """
        执行登出
        """
        exit_url = 'https://uis.fudan.edu.cn/authserver/logout?service=/authserver/login'
        expire = self.get(exit_url).headers.get('Set-Cookie')
        return  expire

    def close(self):
        """
        执行登出并关闭会话
        """
        fuck = self.logout()
        self.session.close()
        return fuck

    def cookie(self, refresh = '0'):
        co = self.session.cookies.get_dict()
        co['refresh'] = refresh
        return "; ".join([str(x)+"="+str(y) for x,y in co.items()])
        
    def get(self, url, *arg, headers={}, **kw):
        headers['Cookies'] = self.cookie()
        url = getVPNUrl(url)
        return self.session.get(url, *arg, headers=headers, **kw)
        
    def post(self, url, *arg, headers={}, **kw):
        headers['Cookies'] = self.cookie()
        url = getVPNUrl(url)
        return self.session.post(url, *arg, headers=headers, **kw)

##a = WebVPN('1930***', '***')
##print(a.login())
##b = a.get('https://www.cnki.net/')
##with open('nmb.txt','wb') as f:
##	f.write(b.content)
##print(a.close())
