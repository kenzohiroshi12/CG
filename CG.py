import os, time, sys, uuid, string, random, re
from os import system as sm
from sys import platform as pf
from time import sleep as sp
try:
    import requests, bs4, rich
    from rich import print as rp
    from rich.panel import Panel as pan
    from requests import get as gt
    from requests import post as pt
    from bs4 import BeautifulSoup
except ModuleNotFoundError:
    sm('python -m pip install requests bs4 rich')

#colors
R="[bold red]"
G="[bold green]"
Y="[bold yellow]"
B="[bold blue]"
M="[bold magenta]"
P="[bold violet]"
C="[bold cyan]"
W="[bold white]"
r="\033[1;31m"
g="\033[1;32m"
y="\033[1;33m"
b="\033[1;34m"
m="\033[1;35m"
c="\033[1;36m"

w="\033[1;37m"
#randc
def randc():
    randcolor=random.choice([R,G,Y,B,M,P,C,W])
    return randcolor
#logo
def logo():
    rp(pan("""%s                     ######   ######
                    ##    ## ##    ##
                    ##       ##    
                    ##       ##    
                    ##       ##
                    ##       ##   ####
                    ##       ##    ##
                    ##    ## ##    ##
                     ######   ######"""%(randc()),title="%sCOOKIE GETTER"%(Y),subtitle="%sDEVELOP BY KENZO"%(R),border_style=f"bold purple"))
#clear
def clear():
    if pf in ['win32','win64']:
        sm('cls')
    else:
        sm('clear')
    logo()
#main
def main():
    clear()
    user=input("%s(USER ID/EMAIL):~ "%(c))
    passw=input("%s(PASSWORD):~ "%(c))
    clear()
    rp(pan("%s[%s1%s]%s COOKIE 1(datr, fr, xs)\n%s[%s2%s]%s COOKIE 2(c_user w/ token)\n%s[%s3%s]%s EXIT"%(Y,C,Y,G,Y,C,Y,G,Y,C,Y,R),border_style="bold purple"))
    try:
        select=int(input("%sChoose Number: %s"%(c,y)))
    except ValueError:
        rp("%sWag kang tanga Number nga eh"%(R))
        main()
    if select == 1:
        datr(user,passw)
    elif select == 2:
        cuser(user,passw)
    else:
        sys.exit("\033[1;31mQUITTING")
def datr(user,passw):
    session=requests.Session()
    headers = {
        'authority': 'free.facebook.com',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*[inserted by cython to avoid comment closer]/[inserted by cython to avoid comment closer]*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'max-age=0',
        'content-type': 'application/x-www-form-urlencoded',
        'dpr': '3',
        'origin': 'https://free.facebook.com',
        'referer': 'https://free.facebook.com/login/?email=%s'%(user),
        'sec-ch-prefers-color-scheme': 'dark',
        'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
        'sec-ch-ua-full-version-list': '"Not-A.Brand";v="99.0.0.0", "Chromium";v="124.0.6327.1"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
        'viewport-width': '980',
        }
    getlog = session.get(f'https://free.facebook.com/login.php')
    idpass ={"lsd":re.search('name="lsd" value="(.*?)"', str(getlog.text)).group(1),"jazoest":re.search('name="jazoest" value="(.*?)"', str(getlog.text)).group(1),"m_ts":re.search('name="m_ts" value="(.*?)"', str(getlog.text)).group(1),"li":re.search('name="li" value="(.*?)"', str(getlog.text)).group(1),"try_number":"0","unrecognize_tries":"0","email":user,"pass":passw,"login":"Log In","bi_xrwh":re.search('name="bi_xrwh" value="(.*?)"', str(getlog.text)).group(1),}
    comp=session.post("https://free.facebook.com/login/device-based/regular/login/?shbl=1&refsrc=deprecated",headers=headers,data=idpass,allow_redirects=False)
    drax=session.cookies.get_dict().keys()
    cookie=";".join([key+"="+value for key,value in session.cookies.get_dict().items()])
    if "c_user" in drax:
        clear()
        print("%sUSERID/EMAIL: %s%s\n%sPASSWORD: %s%s"%(c,g,user,c,g,passw)) 
        print("%sYOUR COOKIE: %s%s"%(c,r,cookie))
        input("%sPress Enter to go back in Main menu"%(g))
        main()
    elif "checkpoint" in drax:
        clear()
        print("%sACCOUNT CHECKPOINT"%(r))
        input("%sPress Enter to go back in Main menu"%(g))
        main()
    else:
        clear()
        print("%sInvalid Username Or Password"%(g))
        input("%sPress Enter to go back in Main menu"%(g))
        main()

#c_user w/ token
def cuser(user,passw):
    accessT="256002347743983|374e60f8b9bb6b8cbb30f78030438895"
    accessToken = '350685531728|62f8ce9f74b12f84c123cc23437a4a32'
    data={
          'adid': f'{uuid.uuid4()}',
          'format': 'json',
          'device_id': f'{uuid.uuid4()}',
          'cpl': 'true',
          'family_device_id': f'{uuid.uuid4()}',
          'credentials_type': 'device_based_login_password',
          'error_detail_type': 'button_with_disabled',
          'source': 'device_based_login',
          'email': user,
          'password': passw,
          'access_token': accessToken,
          'generate_session_cookies': '1',
          'meta_inf_fbmeta': '',
          'advertiser_id': f'{uuid.uuid4()}',
          'currently_logged_in_userid': '0',
          'locale': 'en_US',
          'client_country_code': 'US',
          'method': 'auth.login',
          'fb_api_req_friendly_name': 'authenticate',
          'fb_api_caller_class': 'com.facebook.account.login.protocol.Fb4aAuthHandler',
          'api_key':f'62f8ce9f74b12f84c123cc23437a4a32',
          }
    headers={
          'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 8.0.0; SM-A720F Build/R16NW) [FBAN/Orca-Android;FBAV/196.0.0.29.99;FBPN/com.facebook.orca;FBLC/en_US;FBBV/135374479;FBCR/SMART;FBMF/samsung;FBBD/samsung;FBDV/SM-A720F;FBSV/8.0.0;FBCA/armeabi-v7a:armeabi;FBDM/{density=3.0,width=1080,height=1920};FB_FW/1;]",
          'Content-Type': 'application/x-www-form-urlencoded',
          'Host': 'graph.facebook.com',
          'X-FB-Net-HNI': str(random.randint(10000,99999)),
          'X-FB-SIM-HNI': str(random.randint(10000,99999)),
          'X-FB-Connection-Type': 'MOBILE.LTE',
          'X-Tigon-Is-Retry': 'False',
          'x-fb-session-id': 'nid=jiZ+yNNBgbwC;pid=Main;tid=132;nc=1;fc=0;bc=0;cid=62f8ce9f74b12f84c123cc23437a4a32',
          'x-fb-device-group': str(random.randint(1000,9999)),
          'X-FB-Friendly-Name': 'ViewerReactionsMutation',
          'X-FB-Request-Analytics-Tags': 'graphservice',
          'X-FB-HTTP-Engine': 'Liger',
          'X-FB-Client-IP': 'True',
          'X-FB-Connection-Bandwidth' : str(random.randint(20000000,30000000)),
          'X-FB-Server-Cluster': 'True',
          'x-fb-connection-token': f'62f8ce9f74b12f84c123cc23437a4a32'
          #"d29d67d37eca387482a8a5b740f84f62",
          #str(uuid.uuid4()).replace('-','')
          }
    pos=requests.post("https://b-graph.facebook.com/auth/login",headers=headers,data=data,allow_redirects=False).json()
    if "session_key" in pos:
        clear()
        print("%sUSER ID/EMAIL: %s%s\n%s\n%sPASSWORD: %s%s\n%s\n%sCOOKIE: %s%s\n%s\n%sACCESS_TOKEN: %s%s"%(g,c,user,"\033[1;32m="*os.get_terminal_size().columns,g,c,passw,"\033[1;32m="*os.get_terminal_size().columns,g,c,';'.join(i['name']+'='+i['value'] for i in pos['session_cookies']),"\033[1;32m="*os.get_terminal_size().columns,g,c,pos['access_token']))
        input("\nPress Enter To Go back in Main menu")
        main()
    else:
        print("%sINVALID/CHECKPOINT"%(r))
        input("\033[1;36mPress Enter To Go Back In Main Menu")
        main()
main()