import hashlib
import os
import sys
import time
import traceback
from threading import Thread

import requests


def login_anonymous():
    r = s.post(
        url = 'https://www.wenshushu.cn/ap/login/anonymous',
        json = {
            "dev_info":"{}"
        }
    )
    return r.json()['data']['token']

def download(url):
    def get_tid(token):
        r = s.post(
            url = 'https://www.wenshushu.cn/ap/task/token',
            json = {
                'token': token
            }
        )
        return r.json()['data']['tid']

    def mgrtask(tid):
        r = s.post(
            url = 'https://www.wenshushu.cn/ap/task/mgrtask',
            json = {
                'tid': tid,
                'password': ''
            }
        )
        rsp = r.json()
        expire = rsp['data']['expire']
        days, remainder = divmod(int(float(expire)),3600*24)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        print(f'文件过期时间:{days}天{hours}时{minutes}分{seconds}秒')

        file_size = rsp['data']['file_size']
        print(f'文件大小:{round(int(file_size)/1024**2,2)}MB')
        return rsp['data']['boxid'], rsp['data']['ufileid'] # pid

    def list_file(tid):
        bid, pid = mgrtask(tid)
        r = s.post(
            url = 'https://www.wenshushu.cn/ap/ufile/list',
            json = {
                "start":0,
                "sort":{
                    "name":"asc"
                },
                "bid":bid,
                "pid":pid,
                "type":1,
                "options":{
                    "uploader":"true"
                },
                "size":50
            }
        )
        rsp = r.json()
        filename = rsp['data']['fileList'][0]['fname']
        fid = rsp['data']['fileList'][0]['fid']
        print(f'文件名:{filename}')
        sign(bid, fid, filename)

    def down_handle(url, filename):
        print('开始下载!',end='\r')
        r = s.get(url)
        with open(filename, 'wb') as f:
            f.write(r.content)
            f.close()
        print('下载完成!')

    def sign(bid, fid, filename):
        r = s.post(
            url = 'https://www.wenshushu.cn/ap/dl/sign',
            json = {
                'bid': bid,
                'fid': fid
            }
        )
        url = r.json()['data']['url']
        down_handle(url, filename)

    if len(url.split('/')[-1]) == 16:
        token = url.split('/')[-1]
        tid = get_tid(token)
    elif len(url.split('/')[-1]) == 11:
        tid = url.split('/')[-1]

    list_file(tid)

def upload(filePath):
    file_size = os.path.getsize(filePath)
    ispart = True if file_size > 2097152 else False

    def read_file():
        read_size = 2097152
        partnu = 0
        with open(filePath,"rb") as f:
            while True:
                block = f.read(read_size)
                partnu += 1
                if block:
                    yield block, partnu
                else:
                    return

    def sha1_str(s):
        cm = hashlib.sha1(s.encode('utf-8')).hexdigest()
        return cm

    def calc_file_hash(type, block=None):
        read_size = 2097152 if ispart else None
        if not block:
            block = open(filePath,'rb').read(read_size)
        if type == "md5":
            hash_code = hashlib.md5(block).hexdigest()
        elif type == "SHA1":
            hash_code = hashlib.sha1(block).hexdigest()
        return hash_code

    def storage():
        r = s.post(
            url = 'https://www.wenshushu.cn/ap/user/storage'
        )
        rsp = r.json()
        rest_space = int(rsp['data']['rest_space'])
        send_space = int(rsp['data']['send_space'])
        storage_space = rest_space + send_space
        print('当前已用空间:{}GB,剩余空间:{}GB,总空间:{}GB'.format(
            round(send_space / 1024**3, 2),
            round(rest_space / 1024**3, 2),
            round(storage_space / 1024**3, 2)
        ))

    def userinfo():
        s.post(
            url = 'https://www.wenshushu.cn/ap/user/userinfo'
        )    

    def addsend():
        userinfo()
        storage()
        r = s.post(
            url = 'https://www.wenshushu.cn/ap/task/addsend',
            json = {
                "sender":"",
                "remark":"",
                "isextension":False,
                "pwd":"",
                "expire":2,
                "recvs":[
                    "social",
                    "public"
                ],
                "file_size":file_size,
                "file_count":1
            }
        )
        rsp = r.json()
        if rsp["code"] == 1021:
            print(f'操作太快啦！请{rsp["message"]}秒后重试')
            os._exit(0)
        data = rsp["data"]
        bid, ufileid, tid = data["bid"], data["ufileid"], data["tid"]
        upId = get_up_id(bid, ufileid, tid, file_size)
        return bid, ufileid, tid, upId

    def get_up_id(bid: str, ufileid: str, tid: str, file_size: int):
        r = s.post(
            url="https://www.wenshushu.cn/ap/uploadv2/getupid",
            json={
                "preid": ufileid,
                "boxid": bid,
                "linkid": tid,
                "utype":"sendcopy",
                "originUpid":"",
                "length": file_size,
                "count":1
            }
        )
        return r.json()["data"]["upId"]

    def psurl(fname, upId, file_size, partnu=None):
        payload = {
            "ispart":ispart,
            "fname":fname,
            "fsize":file_size,
            "upId": upId,
        }
        if ispart:
            payload["partnu"] = partnu
        r = s.post(
            url = "https://www.wenshushu.cn/ap/uploadv2/psurl",
            json = payload
        )
        rsp = r.json()
        url = rsp["data"]["url"]
        return url

    def copysend(boxid, taskid, preid):
        r = s.post(
            url = 'https://www.wenshushu.cn/ap/task/copysend',
            json = {
                'bid': boxid,
                'tid': taskid,
                'ufileid': preid
            }
        )
        rsp = r.json()
        print(f"个人管理链接：{rsp['data']['mgr_url']}")
        print(f"公共链接：{rsp['data']['public_url']}")

    def fast():
        boxid, preid, taskid, upId = addsend()
        cm1, cs1 = calc_file_hash("md5"), calc_file_hash("SHA1")
        cm = sha1_str(cm1)
        name = filePath.split('/')[-1]

        payload = {
            "hash":{
                "cm1":cm1, # md5
                "cs1":cs1, # SHA1
            },
            "uf":{
                "name": name,
                "boxid":boxid,
                "preid":preid
            },
            "upId": upId
        }

        if not ispart:
            payload['hash']['cm'] = cm # 把md5用SHA1加密
        for _ in range(2):
            r = s.post(
                url = 'https://www.wenshushu.cn/ap/uploadv2/fast',
                json = payload
            )
            rsp = r.json()
            can_fast = rsp["data"]["status"]
            ufile = rsp['data']['ufile']
            if can_fast and not ufile:
                hash_codes = ''
                for block, _ in read_file():
                    hash_codes += calc_file_hash("md5", block)
                payload['hash']['cm'] = sha1_str(hash_codes)
            elif can_fast and ufile:
                print(f'文件{name}可以被秒传！')
                getprocess(upId)
                copysend(boxid, taskid, preid)
                os._exit(0)

        return name, taskid, boxid, preid, upId

    def getprocess(upId: str):
        while True:
            r = s.post(
                url="https://www.wenshushu.cn/ap/ufile/getprocess",
                json={
                    "processId": upId
                }
            )
            if r.json()["data"]["rst"] == "success":
                return True
            time.sleep(1)

    def complete(fname, upId, tid, boxid, preid):
        s.post(
            url = "https://www.wenshushu.cn/ap/uploadv2/complete",
            json = {
                "ispart":ispart,
                "fname": fname,
                "upId": upId,
                "location":{
                    "boxid":boxid,
                    "preid":preid
                }
            }
        )
        copysend(boxid, tid, preid)

    def file_put(url, block=open(filePath, 'rb').read()):
        requests.put(url=url, data=block)
        if ispart:
            task.pop(0)
        
    def upload_main():
        global task
        threads = []
        task = []
        fname, tid, boxid, preid, upId = fast()
        if ispart:
            print('文件正在被分块上传！')
            for block, partnu in read_file():
                url  = psurl(fname, upId, len(block), partnu)
                t = Thread(target=file_put,args=(url,block))
                threads.append(t)
                task.append(1)
            for thread in threads:
                thread.start()
            while True:
                sp = (len(threads)-len(task)) / len(threads) * 100
                print(f'分块进度:{int(sp)}%',end='\r')
                if sp == 100:
                    print('上传完成:100%')
                    break
            for thread in threads:
                thread.join()
        else:
            print('文件被整块上传！')
            url  = psurl(fname, upId, file_size)
            file_put(url)

        complete(fname, upId, tid, boxid, preid)
        getprocess(upId)
    upload_main()

if __name__ == "__main__":
    s = requests.session()
    s.headers['x-token'] = login_anonymous()
    try:
        command = sys.argv[1]
        if command == 'upload':
            file = sys.argv[2]
            upload(file)
        elif command == 'download':
            url = sys.argv[2]
            download(url)
    except IndexError:
        print('请输入正确命令\n',
            '上传:[python wss.py upload "file.exe"]\n',
            '下载:[python wss.py download "url"]')
    except Exception as e:
        print(f"上传失败：{e}")
