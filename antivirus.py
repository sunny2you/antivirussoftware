import sys
import hashlib
VirusDB=[
    '44d88612fea8a8f36de82e1278abb02f:EICAR Test',
    '77bff0b143e4840ae73d4582a8914a43:Dummy Test'
]
vdb = []
vsize=[]

def MakeVirusDB() :
    for pattern in VirusDB:
        t=[]
        v=pattern.split(':')
        t.append(v[0])
        t.append(v[1])
        vdb.append(t)

#악성코드를 검사한다
def SearchVDB(fmd5):
    for t in vdb:
        if t[0]==fmd5: #MD5 해시가 같은지 비교
            return True, t[1]
        
    return False,' '



if __name__=='__main__' :
    MakeVirusDB()

    if len(sys.argv)!=2:
        print ('Usage : antivirus.py [file]')
        # sys.exit(0)

    fname = sys.argv[1] #악성코드 검사 대상 파일

    fp= open(fname,'rb')
    buf=fp.read()
    fp.close()

    m=hashlib.md5()
    m.update(buf)
    fmd5=m.hexdigest()

    ret, vname = SearchVDB(fmd5)
    
    if ret==True:
        print(f"{fname} : {vname}")
        # os.remove(fname)

    else:
        print(f"{fname}:ok")

