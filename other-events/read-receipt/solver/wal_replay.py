import struct, shutil, sqlite3, zlib, json, hashlib
d=open('catalog.db-wal','rb').read()
magic,ver,pgsz,ckpt,s1,s2,c1,c2 = struct.unpack_from('>IIIIIIII', d, 0)
frames=[]; off=32
while off+24 <= len(d):
    pg, commit, fs1, fs2, cc1, cc2 = struct.unpack_from('>IIIIII', d, off)
    frames.append((pg,commit,d[off+24:off+24+pgsz]))
    off += 24+pgsz
base=open('catalog.db','rb').read()
txs=[]; cur=[]
for f in frames:
    cur.append(f)
    if f[1]: txs.append(cur); cur=[]
for ti,t in enumerate(txs):
    img=bytearray(base)
    for pg,commit,data in t:
        if len(img) < pg*pgsz: img.extend(b'\0'*(pg*pgsz-len(img)))
        img[(pg-1)*pgsz:pg*pgsz]=data
    open('tx%d.db'%ti,'wb').write(img)
    print('=== tx',ti)
    try:
        c=sqlite3.connect('tx%d.db'%ti)
        for name,fmt,val in c.execute('select name,format,value from catalog'):
            print(' catalog',name,fmt,len(val),hashlib.sha256(val).hexdigest()[:16])
            try:
                j=json.loads(zlib.decompress(val))
                print('  stream',j['stream'].get('generation'),j['stream'].get('bytes'),j['stream'].get('sha256')[:16],'nrows',len(j['rows']))
                print('  first rows', [r['at'] for r in j['rows'][:4]])
            except Exception as e: print('  decompress fail',e)
        for r in c.execute('select ticket,state,catalog_name,length(view),length(sealed) from jobs'):
            print(' job',r[0].hex(),r[1],r[2],r[3],r[4])
        for name,val in c.execute('select name,value from device'):
            print('  dev',name,val)
    except Exception as e:
        print(' ERR',e)
