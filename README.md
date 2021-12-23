[CLICK THIS GO TO MY PAGESITE](https://dxhm.github.io/LINUX-PENETRATION)
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
# Burp Suite
# BeFF测试Xss漏洞
# Python Hacking
