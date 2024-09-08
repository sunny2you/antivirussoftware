import sys
import zlib
import hashlib
import os

def main():
    if len(sys.argv) != 2:
        print('Usage : kamke.py [file]')
        return
    
    fname=sys.argv[1] #암호화 대상 파일
    tname=fname
    
    fp=open(tname, 'rb') #대상 파일 읽기
    buf=fp.read()
    fp.close()

    buf2 = zlib.compress(buf) #대상 파일 내용을 압축한다

    buf3 = ''
    for c in buf2 : #0xFF로 압축된 내용을 XOR한다
        buf3+=chr(c^0xFF)

    buf4='KAVM'+buf3 #헤더를 생성한다

    f=buf4
    for i in range(3) : #지금까지의 내용을 MD5로 구한다
        md5=hashlib.md5()
        md5.update(f.encode('utf-8'))
        f=md5.hexdigest()

    buf4+=f #MD5를 암호화된 내용 뒤에 추가한다

    kmd_name=fname.split('.')[0]+'.kmd'
    fp=open(kmd_name,'wb')
    fp.write(buf4.encode('utf-8'))
    fp.close()

    print(f"{fname} -> {kmd_name}")

if __name__=='__main__':
    main()
