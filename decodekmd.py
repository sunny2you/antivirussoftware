import hashlib
import zlib
def DecodeKMD(fname) : 
    try:
        fp=open(fname,'rb')
        buf=fp.read()
        fp.close()
        #암호화 과정을 반대로 진행한다
        buf2=buf[:-32] #암호화 내용을 분리한다
        fmd5=buf[-32:] #MD5를 분리한다

        f=buf2
        for i in range(3): #암호화 내용의 MD5를 구한다. 
            md5=hashlib.md5() 
            md5.update(f)
            f=md5.hexdigest()

        if f!=fmd5: #구한 MD5와 파일에서 분리된 MD5가 같은지 확인한다.
            raise SystemError
        
        buf3=''
        for c in buf2[4:] :
            buf3+=chr(c^0xFF) #0xFF XOR연사

        buf4=zlib.decompress(buf3)
        return buf4 #성공했다면 복호화된 내용을 리턴한다
    
    except :
        pass

    return None
