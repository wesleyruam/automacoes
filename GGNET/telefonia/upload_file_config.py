import os 
import requests
import socket
import configparser
import ipaddress
import string
import sys
import logging
import concurrent.futures
from tabulate import tabulate
from optparse import OptionParser
from InquirerPy import prompt
from tqdm import tqdm

class DeviceManager:
    def __init__(self, password, username):
        self._password = password
        self._username = username

        self._session_id = None
        self._cookies = None

        self._login = False

    def _authenticate(self, host_ip):
        login_url = f"http://{host_ip}/cgi-bin/dologin"
        login_payload = {
            'username': self._username,
            'password': self._password
        }

        request_headers = {
            'Cache-Control': 'max-age=0',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': '*/*',
            'Origin': f'http://{host_ip}/',
            'Referer': f'http://{host_ip}/',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
            'Connection': 'keep-alive'
        }

        try:
            response = requests.post(login_url, data=login_payload, headers=request_headers, timeout=3)
            if response.status_code == 200:
                requisicoes_logger.info(f"Log-in realizado com sucesso no IP: {host_ip}")
                self._login = True
                with open('login_ips.txt', 'a') as login_file:
                    login_file.write(f"{host_ip}\n")
                self._cookies = response.cookies
                self._session_id = response.cookies.get('session-identity')
        except requests.exceptions.ConnectTimeout:
            requisicoes_logger.error(f"Timeout ao tentar realizar o log-in no ip {host_ip}")
            return None

    def fetch_vendor_info(self, host_ip):
        if (self._login == False):
            self._authenticate(host_ip)

        api_url = f"http://{host_ip}/cgi-bin/api.values.get"

        request_headers = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
            "Accept": "*/*",
            "Accept-Language": "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3",
            "Content-Type": "application/x-www-form-urlencoded",
            "Cache-Control": "max-age=0",
            "Referer": f"http://{host_ip}/",
        }

        request_body = (
            "request=PIPStatus:PNAT_TYPE:PNAT_TURN:P52:P414:P514:P614:P714:P814:vendor_fullname:"
            "P67:Pipv4:Pipv6:Pvpn_ip:Psubnet_web:Pgateway_web:Pdns1_web:Pdns2_web:P211"
            f"&sid={self._session_id}"
        )

        try:
            response = requests.post(api_url, headers=request_headers, cookies=self._cookies, data=request_body, timeout=3)
            if response.status_code == 200:
                requisicoes_logger.info(f"Sucesso ao extrair vendor do IP {host_ip}")
                return response.json().get('body', {}).get('vendor_fullname')
            return None
        except Exception as e:
            requisicoes_logger.info(f"Erro ao extrair vendor do IP {host_ip}")
            return None

    def upload_configuration_file(self, file_content, file_name, host_ip):
        if (self._login == False):
            self.authenticate(host_ip)
        
        upload_url = f"http://{host_ip}/cgi-bin/upload_cfg"
        
        request_headers = {
            "Cache-Control": "max-age=0",
            "Upgrade-Insecure-Requests": "1",
            "Origin": f"http://{host_ip}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, Gecko) Chrome/127.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Referer": f"http://{host_ip}/",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
            "Connection": "keep-alive",
        }
        
        file_data = {
            "file": (file_name, file_content, "text/plain"),
            "fname": (None, file_name),
            "sid": (None, self._session_id),
        }

        cookies_dict = {
            "session-role": "admin",
            "session-identity": self._session_id,
        }
        cookies_dict.update(self._cookies or {})

        response = requests.post(upload_url, headers=request_headers, files=file_data, cookies=cookies_dict)
        
        return response.status_code == 200

    def ping_ip(self):
        try:
            socket.setdefaulttimeout(3)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                result = s.connect_ex((self._host_ip, 80))
                return result == 0
        except socket.error:
            return False


class ConfigFileManager:
    def __init__(self, filename) -> None:
        _abs_path = os.path.dirname(os.path.abspath(__file__))

        with open(os.path.join(_abs_path, filename), 'r') as file:
            _lines = file.readlines()

        self._filename = filename
        self._data = {}

        for _line in _lines:
            if '=' in _line:
                _chave, _valor = _line.strip().split('=', 1)
                self._data[_chave] = _valor

    def get_value(self, key):
        return self._data.get(key, None)
    
    def get_all_values(self):
        return self._data

    def set_value(self, key, value):
        self._data[key] = value

    def save_file(self):
        _abs_path = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(_abs_path, self._filename), 'w') as file:
            for key, value in self._data.items():
                file.write(f'{key}={value}\n')
                file.flush()
                



class cli_manager:
    def __init__(self):    
        
        abs_path = os.path.dirname(os.path.abspath(__file__))
        parser = OptionParser()
        config = configparser.ConfigParser()
        
        parser.add_option('--Fi', '--filename_config_ini', dest="filename_config_ini", help="Nome do arquivo de configuração .ini", metavar="ARQUIVO", default="config.ini")
        parser.add_option('--Fc', '--filename_config_upload', dest='filename_config_upload', help="Nome do arquivo na qual será usando para realizar o upload .txt", metavar="ARQUIVO", default="config.txt")
        parser.add_option('--Si', '--scan_ips', dest="scan_ips", action="store_true", help="Faz scan dos IPs de telefones, e tenta realizar o login")
        parser.add_option('--Uf', '--upload_file', dest="upload_file", action='store_true', help="Realiza o upload do arquivo de configuração no IP listado")

        (options, args) = parser.parse_args()
        
        config.read(os.path.join(abs_path, options.filename_config_ini))
        
        
        self.username = config['default_login']['username']
        self.password = config['default_login']['password']
        self.ip = config['ip_range']['ipaddress_range']
        
        
        self.network = ipaddress.ip_network(self.ip, strict=False)
        self.total_ips = self.network.num_addresses
        
        #self.device_manager = DeviceManager()
        self.config_file_manager = ConfigFileManager(options.filename_config_upload)
        self.device_manager = DeviceManager(self.username, self.password)

        if options.scan_ips:
            results = self.progress(self.device_manager.fetch_vendor_info, self.total_ips)
            with open(os.path.join(abs_path, 'ips_ativos.txt'), 'w') as file:
                for ip in results:
                    file.write(str(ip) + '\n')
                    file.flush()
        
        if options.upload_file:
            ramal_inicial = config['config_file_pattern']['ramal_inicial']
            ramal_final = config['config_file_pattern']['ramal_final']
            dominio = config['config_file_pattern']['dominio']
            senha_template = config['config_file_pattern']['senha']
            template = string.Template(senha_template)

            with open(os.path.join(abs_path, 'ips_ativos.txt'), 'r') as file:
                lines = file.readlines()

                if len(lines) > 1:
                    ramal = int(ramal_inicial)
                    for ip in lines:
                        senha = template.substitute(ramal=ramal)
                        data = [[str(ip), str(ramal), str(dominio), str(senha)]]
                        print("\r", tabulate(data, headers=["IP", "RAMAL", "DOMÍNIO", "SENHA"], tablefmt="grid"))
                        

                        question = [
                            {
                                'type' : 'list',
                                'message' : f'Deseja realmente realizar o upload para o IP: {ip}',
                                'name' : 'action',
                                'choices' : ['Aceitar', 'Pular', 'Parar']
                            }
                        ]

                        resposta = prompt(question)['action']

                        if resposta == "Aceitar":
                            #definição dos valores no arquivo de configuração:

                            # Definindo o ramal
                            self.config_file_manager.set_value("P35", ramal)
                            self.config_file_manager.set_value("P36", ramal)
                            self.config_file_manager.set_value("P270", ramal)
                            self.config_file_manager.set_value("P3", ramal)

                            #Definindo o SIP Server(Domínio)
                            self.config_file_manager.set_value("P47", dominio)
                            
                            #Definindo a senha(Authenticate Password)
                            self.config_file_manager.set_value("P34", senha)

                            self.config_file_manager.save_file()

                            ramal += 1
                        elif resposta == "Pular":
                            continue
                        elif resposta == "Parar":
                            sys.exit(1)
                    
    
    def progress(self, action, total_ips):
        results = []
        with tqdm(total=total_ips, desc="Progresso", unit='ip') as progress_bar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=300) as executor:
                futures = {executor.submit(action, ip): ip for ip in self.network.hosts()}

                for future in concurrent.futures.as_completed(futures):
                    ip = futures[future]
                    try:
                        result = future.result()
                        if result:
                            results.append(ip)
                        progress_bar.update(1)
                    except Exception as e:
                        progress_bar.update(1)

        return results
        
        




if __name__ == '__main__':
    global upload_logger, requisicoes_logger

    upload_logger = logging.getLogger('upload_logger')
    upload_logger.setLevel(logging.DEBUG)  # Definindo o nível de log

    upload_handler = logging.FileHandler('upload_file.log')
    upload_handler.setLevel(logging.DEBUG)
    upload_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

    upload_logger.addHandler(upload_handler)

    # Criando o logger para requisicoes.log
    requisicoes_logger = logging.getLogger('requisicoes_logger')
    requisicoes_logger.setLevel(logging.DEBUG)  # Definindo o nível de log

    requisicoes_handler = logging.FileHandler('requisicoes.log')
    requisicoes_handler.setLevel(logging.DEBUG)
    requisicoes_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

    requisicoes_logger.addHandler(requisicoes_handler)

    cli_manager()
    
    
    
    
    
