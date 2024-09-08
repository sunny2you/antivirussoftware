import os
import hashlib

def SearchVDB(vdb, fmd5):
    for t in vdb:
        if t[0]==fmd5: #MD5 해시가 같은지 비교
            return True, t[1]
        
    return False,' '

def ScanMD5(vdb, vsize, fname):
    ret=False #악성코드 발견 유무
    vname='' # 발견된 악성코드명

    size=os.path.getsize(fname)

    if vsize.count(size):
        fp= open(fname,'rb')
        buf=fp.read()
        fp.close()

        m=hashlib.md5()
        m.update(buf)
        fmd5=m.hexdigest()

        ret, vname = SearchVDB(fmd5) # 악성코드를 검사한다

    return ret, vname

def ScanStr(fp, offset, mal_str) :
    size=len(mal_str)

    fp.seek(offset)
    buf=fp.read(size)
    if buf == mal_str:
        return True
    else :
        return False

def ScanVirus(vdb, vsize, sdb, fname) :
    #MD5해시 이용
    ret, vname = ScanMD5(vdb,vsize,fname)
    if ret==True :
        return ret,vname
    
    #특정 위치 검색법 이용
    fp=open(fname,'rb')
    for t in sdb :
        if ScanStr(fp, t[0], t[1])==True:
            ret=True
            vname=t[2]
            break
    fp.close()

    return ret,vname