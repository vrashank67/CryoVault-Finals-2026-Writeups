from coremem import Core,b
import json,struct,sqlite3
c=Core();objs=json.loads((b/'objects.json').read_text());books=[o for o in objs if o['class']=='ledger/Service$Book']
snaps={}
for i,o in enumerate(books):
 ctx=o['context']
 print('BOOK',i,hex(ctx))
 for kind,off in [('r',0),('p',8)]:
  db=c.u64(ctx+off)
  if db in snaps: print(kind,'reuse',snaps[db]['path']);continue
  adb=c.u64(db+32);bt=c.u64(adb+8);shared=c.u64(bt+8);pager=c.u64(shared);wal=c.u64(pager+296);pcache=c.u64(pager+288)
  fn=c.u64(pager+216);filename=c.read(fn,200).split(b'\0')[0].decode();name=filename.split('/')[-1]
  mx=c.u32(wal+88);np=c.u32(wal+92);ps=c.u32(pager+200);dbsz=c.u32(pager+32)
  print(kind,hex(db),name,'mxFrame',mx,'nPage',np,'dbSize',dbsz,'readLock',c.u32(wal+60))
  data=bytearray((b/'rootfs/srv/ledger/state'/name).read_bytes());wd=(b/'rootfs/srv/ledger/state'/(name+'-wal')).read_bytes()
  frames=(len(wd)-32)//(ps+24)
  print('pagesize',ps,'walframes',frames)
  for f in range(mx):
   pos=32+f*(ps+24);pgno=struct.unpack_from('>I',wd,pos)[0]
   if len(data)<pgno*ps:data.extend(b'\0'*(pgno*ps-len(data)))
   data[(pgno-1)*ps:pgno*ps]=wd[pos+24:pos+24+ps]
  dirty=c.u64(pcache);dirtylist=[]
  while dirty:
   pg=c.u32(dirty+48);pd=c.u64(dirty+8);dirtylist.append(pg)
   if len(data)<pg*ps:data.extend(b'\0'*(pg*ps-len(data)))
   data[(pg-1)*ps:pg*ps]=c.read(pd,ps)
   dirty=c.u64(dirty+64)
  print('dirty',dirtylist)
  data=data[:dbsz*ps]
  data[18:20]=b'\1\1'
  dest=b/'snapshots'/f'{name}.{mx}.{db:x}.db';dest.parent.mkdir(exist_ok=True);dest.write_bytes(data)
  cx=sqlite3.connect(dest)
  print('integrity',cx.execute('pragma integrity_check').fetchone())
  result={'path':str(dest),'kind':kind,'file':name,'mx':mx,'dirty':dirtylist,'db':db,'pager':pager}
  snaps[db]=result
(b/'snapshots.json').write_text(json.dumps({str(k):v for k,v in snaps.items()},indent=2))
(b/'contexts.json').write_text(json.dumps([{kind:c.u64(o['context']+off) for kind,off in [('r',0),('p',8)]} for o in books],indent=2))
