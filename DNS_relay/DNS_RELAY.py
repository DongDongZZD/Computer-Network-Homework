import time
import threading
from concurrent.futures import ThreadPoolExecutor
import socket

class DNSRelay:
     def __init__(self, file_name):
          self.file_data = []
          with open(file_name) as file_object:
               for line in file_object:
                    if line != '\n':
                         self.file_data.append(tuple(line.rstrip().split()))
          self.socketRecv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
          self.socketRecv.bind(("localhost", 53))
          self.pool = ThreadPoolExecutor(max_workers = 4)
          self.lock = threading.RLock()
     
     def run(self):
          while True:
               try:
                    message, address = self.socketRecv.recvfrom(1024)
                    self.pool.submit(self.solve, message, address)
               except ConnectionResetError:
                    ...
     
     def solve(self, message, address):
          self.lock.acquire()
          print("\n从 " + address[0] + " 抓取一个包")
          print("---------------------------------开始解析")
          start = time.time()
          # 得到域名
          NAME = ''
          i = 12
          if message[i] != 0:
               while True:
                    for j in range(1, message[i] + 1):
                         NAME = NAME + chr(message[i + j])
                    i = message[i] + i + 1
                    if message[i] == 0:
                         break
                    NAME = NAME + '.'
          # 查询类型
          TYPE = message[i+1:i+3]
          print("域名为：" + NAME)
          print("查询类型为：" + str(TYPE))
          if message[2] >> 3 == 0 and TYPE == b'\x00\x01':
               print('------是标准查询包且查询类型为IPv4地址')
               print('------在配置文件中查找')
               for (ip, domain) in self.file_data:
                    if domain == NAME:
                         print("------找到对应IP地址")
                         response = self.gen_response(message, ip)
                         print("------回答报文生成完毕")
                         self.socketRecv.sendto(response, address)
                         print('------发送回答报文给 ' + address[0])
                         end = time.time()
                         print("---------------------------------解析完毕  用时：%.03f 秒" %(end - start))
                         self.lock.release()
                         break
               else:
                    print('------配置文件中未找到')
                    self.forward(message, address, start)
          elif message[2] >> 3 == 0 and TYPE == b'\x00\x1C':
               for (ip, domain) in self.file_data:
                    if domain == NAME and ip == "0.0.0.0":
                         print("------此查询IPv6报文的域名对应的IPv4地址在配置文件中为‘0.0.0.0’")
                         response = self.gen_response(message, ip)
                         print("------回答报文生成完毕")
                         self.socketRecv.sendto(response, address)
                         print('------发送回答报文给 ' + address[0])
                         end = time.time()
                         print("---------------------------------解析完毕  用时：%.03f 秒" %(end - start))
                         self.lock.release()
                         break
               else:
                    print('------其余查询类型')
                    self.forward(message, address, start)

          else:
               print('------其余查询类型')
               self.forward(message, address, start)

     def forward(self, message, address, start):
          forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
          forward_socket.settimeout(5)
          try:
               forward_socket.sendto(message, ('223.5.5.5', 53))
               print('------查询报文转发给远端DNS服务器，其IP地址为：223.5.5.5')
               response, response_addr = forward_socket.recvfrom(1024)
               print('------得到本地DNS服务器的回复')
               self.socketRecv.sendto(response, address)
               print('------转发回答报文给 ' + address[0])
               end = time.time()
               print("---------------------------------解析完毕  用时：%.03f 秒" %(end - start))
               forward_socket.close()
          except ConnectionResetError:
               forward_socket.close()
          except:
               print("------TIME OUT")
               print("---------------------------------解析完毕")
               forward_socket.close()
          self.lock.release()
     
     def gen_response(self, message, ip):
          response = message[:2]
          if ip == "0.0.0.0":
               print("------查询报文已拦截")
               # QR = '1'
               # Opcode = '0000'
               # AA = '0'
               # TC = '0'
               # RD = '1'
               # RA = '1'
               # Z ='0'
               # AD = '0'
               # CD = '0'
               # Rcode = '0011'
               # QDCOUNT = b'\x00\x01'
               # ANCOUNT = b'\x00\x00'
               # NSCOUNT = b'\x00\x00'
               # ARCOUNT = b'\x00\x00'
               response += b'\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00'
               # 问题区域
               response += message[12:]
          else:
               print("------为合法查询报文")
               # QR = '1'
               # Opcode = '0000'
               # AA = '0'
               # TC = '0'
               # RD = '1'
               # RA = '1'
               # Z ='0'
               # AD = '0'
               # CD = '0'
               # Rcode = '0000'
               # QDCOUNT = b'\x00\x01'
               # ANCOUNT = b'\x00\x01'
               # NSCOUNT = b'\x00\x00'
               # ARCOUNT = b'\x00\x00'
               response += b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
               # 问题区域
               response += message[12:]
               # 指针，指向请求部分的域名
               # 高两位识别指针，12为首部区域的长度
               response += b'\xC0\x0C' 
               # 类型为IPv4地址查询，查询类为IN
               response += b'\x00\x01\x00\x01'
               # 生存时间：一天
               response += b'\x00\x01\x51\x80'
               # 资源数据长度
               response += b'\x00\x04'
               ip = ip.split('.')
               for i in range(4):
                    response += int(ip[i]).to_bytes(1, 'big')
          return response

if __name__ == '__main__':
    print("\n======= DNS Relay =======")
    print("服务器:localhost.localdomain")
    file_name = input("\nPlease enter the path of config file:  ")
    print(" ")
    run = DNSRelay(file_name)
    run.run()