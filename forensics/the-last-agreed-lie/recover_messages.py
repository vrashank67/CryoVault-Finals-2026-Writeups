import hashlib,json,pathlib,sqlite3,struct

R=pathlib.Path(__file__).resolve().parent
messages={}
def collect(image,desk,frame):
    image=bytearray(image)
    image[18]=image[19]=1
    con=sqlite3.connect(':memory:')
    con.deserialize(bytes(image))
    try:
        for slot,lease,route,body in con.execute('SELECT slot,lease,route,body FROM inbox'):
            key=f'{desk}:{slot}:{lease}'
            rec={'desk':desk,'slot':slot,'lease':lease,'route':route,'body':body.hex(),'frame':frame}
            if key in messages:
                assert messages[key]['body']==rec['body']
            else:messages[key]=rec
    finally:con.close()

def checksum(b,s=(0,0),endian='<'):
    nums=struct.unpack(endian+str(len(b)//4)+'I',b)
    a,c=s
    for i in range(0,len(nums),2):
        a=(a+nums[i]+c)&0xffffffff
        c=(c+nums[i+1]+a)&0xffffffff
    return a,c

for desk,p in enumerate(sorted((R/'evidence/profiles').glob('*/review.db'))):
    image=bytearray(p.read_bytes()); collect(image,desk,-1)
    wal=(p.parent/'review.db-wal').read_bytes()
    magic,version,ps=struct.unpack_from('>III',wal)
    endian='<' if magic==0x377f0682 else '>'
    cks=checksum(wal[:24],endian=endian)
    assert cks==struct.unpack_from('>II',wal,24)
    salt=wal[16:24]
    frames=(len(wal)-32)//(ps+24); commits=0
    bad_checksums=[]; stale_salts=[]
    for f in range(frames):
        off=32+f*(ps+24)
        head=wal[off:off+24]; page=wal[off+24:off+24+ps]
        if head[8:16]!=salt:stale_salts.append(f)
        cks=checksum(head[:8]+page,cks,endian)
        stored=struct.unpack_from('>II',head,16)
        if cks!=stored:
            bad_checksums.append(f)
        cks=stored
        pg,size=struct.unpack_from('>II',head)
        if len(image)<pg*ps:image.extend(bytes(pg*ps-len(image)))
        image[(pg-1)*ps:pg*ps]=page
        if size:
            del image[size*ps:]
            try:collect(image,desk,f)
            except sqlite3.DatabaseError as exc:print('SNAPSHOT ERROR',desk,f,str(exc))
            commits+=1
    # Older generations and damaged frames are forensic salvage, not valid
    # current SQLite commits. Replay validates each recovered message using
    # its embedded digest and finally the independent receipt commitment.
    print(p.parent.name,'scanned frames',frames,'snapshot boundaries',commits,
          'messages',sum(m['desk']==desk for m in messages.values()),
          'checksum mismatches',len(bad_checksums),'stale salts',len(stale_salts))
(R/'messages.json').write_text(json.dumps(messages,indent=2))
events=json.loads((R/'events.json').read_text())
needed={f'{e[3]}:{e[4]}:{e[5]}' for r in events if (e:=r['event'])[0]==33}
missing=needed-messages.keys()
print('NEEDED',len(needed),'RECOVERED',len(messages),'MISSING',len(missing))
print('MISSING EXAMPLES',list(missing)[:20])
