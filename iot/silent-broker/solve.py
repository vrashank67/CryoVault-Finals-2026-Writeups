#!/usr/bin/env python3
"""SILENT BROKER: reconstruct MQTT delivery, authenticate CB3, decrypt receipt.
Usage: python solve.py EVIDENCE_DIRECTORY
Dependencies: pip install scapy cryptography
"""
import sys,os,tempfile,pathlib
if len(sys.argv)!=2:
 raise SystemExit('Usage: python solve.py EVIDENCE_DIRECTORY')
EVIDENCE=pathlib.Path(sys.argv[1]).resolve()
original_directory=pathlib.Path.cwd()
with tempfile.TemporaryDirectory(prefix='silent-broker-') as scratch:
 try:
  os.chdir(scratch)
  pathlib.Path('work').mkdir()
  import json,struct,collections,pathlib
  from scapy.all import rdpcap,IP,TCP
  BASE=EVIDENCE
  def u16(b,o=0): return int.from_bytes(b[o:o+2],'big')
  def u32(b,o=0): return int.from_bytes(b[o:o+4],'big')
  def var(b,o):
   v=0;m=1;s=o
   while True:
    a=b[o];o+=1;v+=(a&127)*m;m*=128
    if a<128:return v,o
  def string(b,o):
   n=u16(b,o);o+=2;return b[o:o+n].decode(),o+n
  def db(name):
   b=(BASE/name).read_bytes();o=23;chunks=[]
   while o<len(b):
    typ,n=struct.unpack_from('>II',b,o);o+=8;d=b[o:o+n];o+=n;r={'type':typ}
    if typ==2:
     sid,exp=struct.unpack_from('<Qq',d);plen=u32(d,16);mid,il,ul,tl,port=struct.unpack_from('>5H',d,20);qos,retain=d[30:32];p=32
     vals=[]
     for l in [il,ul,tl,plen]:vals.append(d[p:p+l]);p+=l
     r.update(id=sid,expiry=exp,mid=mid,qos=qos,retain=retain,source=vals[0].decode(),user=vals[1].decode(),topic=vals[2].decode(),payload=vals[3].decode(),props=d[p:].hex())
    elif typ==3:
     sid=int.from_bytes(d[:8],'little');mid,il=struct.unpack_from('>HH',d,8)
     r.update(id=sid,mid=mid,qos=d[12],state=d[13],retain_dup=d[14],direction=d[15],client=d[16:16+il].decode(),props=d[16+il:].hex())
    elif typ==4:r['id']=int.from_bytes(d,'little')
    elif typ==5:
     il,tl=struct.unpack_from('>HH',d,4);r.update(identifier=u32(d),qos=d[8],options=d[9],client=d[12:12+il].decode(),topic=d[12+il:12+il+tl].decode())
    elif typ==6:
     exp=int.from_bytes(d[:8],'little');interval=u32(d,8);mid,il,port,ul=struct.unpack_from('>4H',d,12)
     r.update(expiry=exp,interval=interval,mid=mid,client=d[24:24+il].decode(),user=d[24+il:24+il+ul].decode())
    else:r['hex']=d.hex()
    chunks.append(r)
   return chunks
  def pcap():
   streams={};conns={};ev=[]
   for num,p in enumerate(rdpcap(str(BASE/'plant.pcap')),1):
    if IP not in p or TCP not in p:continue
    ip=p[IP];t=p[TCP];key=(ip.src,t.sport,ip.dst,t.dport)
    if t.flags.S and not t.flags.A:conns[key]=num;conns[(ip.dst,t.dport,ip.src,t.sport)]=num
    payload=bytes(t.payload)
    if not payload:continue
    key=key+(conns.get(key,0),)
    stream=streams.setdefault(key,{'parts':[]});stream['parts'].append((int(t.seq),payload,float(p.time),num))
   for key,s in streams.items():
    parts=s['parts'];base=min(x[0] for x in parts);end=max(x[0]+len(x[1]) for x in parts);b=bytearray(end-base);times={}
    for seq,data,tm,num in parts:
     off=seq-base;b[off:off+len(data)]=data
     for i in range(len(data)):times.setdefault(off+i,(tm,num))
    o=0
    while o<len(b):
     start=o;flag=b[o];n,o=var(b,o+1);d=bytes(b[o:o+n]);o+=n
     tm,num=times[start];e={'time':tm,'packet':num,'conn':key[4],'src':key[0],'sport':key[1],'dst':key[2],'dport':key[3],'type':flag>>4,'flags':flag&15,'hex':d.hex()};ev.append(e)
   ev.sort(key=lambda e:(e['time'],e['packet']))
   clients={};versions={}
   for e in ev:
    d=bytes.fromhex(e['hex']);typ=e['type'];cn=e['conn'];v=versions.get(cn,4)
    try:
     if typ==1:
      proto,p=string(d,0);v=d[p];p+=1;cf=d[p];p+=3;props=b''
      if v==5:l,p=var(d,p);props=d[p:p+l];p+=l
      client,p=string(d,p);clients[cn]=client;versions[cn]=v;e.update(client=client,version=v,connect_flags=cf,props=props.hex(),tail=d[p:].hex())
     elif typ==3:
      topic,p=string(d,0);qos=(e['flags']>>1)&3;mid=None
      if qos:mid=u16(d,p);p+=2
      props=b''
      if v==5:l,p=var(d,p);props=d[p:p+l];p+=l
      e.update(topic=topic,mid=mid,qos=qos,props=props.hex(),payload=d[p:].decode())
     elif typ in [4,5,6,7,8,9,10,11]:e['mid']=u16(d)
     e.setdefault('client',clients.get(cn,'?'))
    except Exception as err:e['error']=str(err)
   return ev
  
  for name in ['mosquitto-pre.db','mosquitto-recovery.db','mosquitto-final.db']:
   pathlib.Path('work/'+name+'.json').write_text(json.dumps(db(name)))
  pathlib.Path('work/events.json').write_text(json.dumps(pcap()))
  
  import json,hashlib,hmac,struct,collections,pathlib
  from cryptography.hazmat.primitives.kdf.hkdf import HKDF
  from cryptography.hazmat.primitives import hashes
  from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
  def hk(ikm,salt,info,n):return HKDF(algorithm=hashes.SHA256(),length=n,salt=salt,info=info.encode()).derive(ikm)
  pre=json.load(open('work/mosquitto-pre.db.json'));lease=json.loads(next(x['payload'] for x in pre if x['type']==2 and x['topic']=='plant/l3/meta/lease/b7/14'))
  records=json.loads((BASE/'provisioning.json').read_text())['records'];gw=json.loads((BASE/'gateway.json').read_text())
  record=next(r for r in records if hashlib.sha256(f"{r['serial']}|{r['revision']}|{r['ticket']}".encode()).hexdigest()[:16]==lease['owner'])
  kek=hk(bytes.fromhex(record['ticket']),bytes.fromhex(gw['provisioning']['plant_salt']),f"KEK|{record['serial']}|{record['revision']}",32)
  root=aes_key_unwrap(kek,bytes.fromhex(next(s['wrapped'] for s in gw['provisioning']['slots'] if s['slot']==lease['slot'])))
  context=f"CB3|edge-b7-14|{lease['route']}|{lease['epoch']}".encode();material=hk(root,bytes.fromhex(lease['salt']),context.decode(),64);cipher,mac=material[:32],material[32:]
  def frame(e):
   try:j=json.loads(e['payload']);b=b''.join(struct.pack('>H',v&65535) for v in j['trim'])
   except:return
   if not b.startswith(b'\xa7\x31'):return
   magic,rev,lane,epoch,counter,count,n=struct.unpack('>2sBBIHHH',b[:14]);d=b[14:14+n];tag=b[14+n:30+n]
   good=hmac.compare_digest(tag,hmac.new(mac,e['topic'].encode()+b'\x00'+b[:14]+d,hashlib.sha256).digest()[:16])
   return dict(lane=lane,epoch=epoch,counter=counter,count=count,n=n,data=d.hex(),valid=good,sample=j['sample'])
  events=json.load(open('work/events.json'));aliases=collections.defaultdict(dict)
  for e in events:
   if e['type']!=3:continue
   props=bytes.fromhex(e['props']);p=0;e['expiry']=None
   while p<len(props):
    typ=props[p];p+=1
    if typ==0x23:
     a=int.from_bytes(props[p:p+2],'big');p+=2
     if e['topic']:aliases[e['conn']][a]=e['topic']
     else:e['topic']=aliases[e['conn']].get(a,'?')
    elif typ==0x02:e['expiry']=int.from_bytes(props[p:p+4],'big');p+=4
    else:raise ValueError(props.hex())
   f=frame(e)
   if f:e['frame']=f
  
  import json,collections,math,pathlib
  pending=collections.defaultdict(dict);routed=[];delivered=[];queued=[];online=True;last_mid=1;checkpoint=False
  def matches(topic):
   a=topic.split('/');return (len(a)==5 and a[:2]==['plant','l3'] and a[-1]=='telemetry') or (len(a)==4 and a[:2]==['factory','line-03'] and a[-1]=='telemetry')
  def allowed(e):
   c=e['client'];t=e['topic']
   if c in ['edge-b7-14','svc-b7-14']:return t=='plant/l3/b7/14/telemetry' or t.startswith('plant/l3/b7/14/telemetry/')
   if c=='edge-b7-41':return t.startswith('factory/line-03/') or t=='plant/l3/b7/41/telemetry' or t.startswith('plant/l3/b7/41/telemetry/')
   return False
  def route(e,time):
   global last_mid
   if not matches(e['topic']):return
   r=dict(e);r['route_time']=time
   if online or e['qos']>0:
    if e['qos']>0:last_mid+=1
    r['archive_mid']=last_mid if e['qos']>0 else 0;routed.append(r)
    if online:
     if not r.get('expires') or int(time)<=r['expires']:delivered.append(r)
    else:queued.append(r)
  for e in events:
   t=e['time'];c=e['client']
   if t>=1792499930 and online and not checkpoint:online=False
   if t>=1792499936 and not checkpoint:
    checkpoint=True
    rec=json.load(open('work/mosquitto-recovery.db.json'));stores={x['id']:x for x in rec if x['type']==2}
    dbpending={x['mid']:json.loads(stores[x['id']]['payload'])['sample'] for x in rec if x['type']==3 and x['direction']==0 and x['client']=='edge-b7-14'}
    actual={k:json.loads(v['payload'])['sample'] for k,v in pending['edge-b7-14'].items()}
    assert actual==dbpending, 'Incoming QoS 2 checkpoint mismatch'
    print('Pending QoS 2 state matches recovery database')
    assert last_mid==85
    print('Recovery archive message ID:',last_mid)
    assert [json.loads(x['payload'])['sample'] for x in queued]==[json.loads(stores[x['id']]['payload'])['sample'] for x in rec if x['type']==3 and x['direction']==1]
    print('Outgoing archive queue matches recovery database')
   if t>=1792499940 and not online and checkpoint:
    online=True
    delivered.extend(x for x in queued if not x.get('expires') or int(t)<=x['expires']);queued=[]
   if e['type']==2 and bytes.fromhex(e['hex'])[0]&1==0:pending[c].clear()
   if e['src']=='10.31.0.1':continue
   if e['type']==3 and allowed(e):
    r=dict(e);r['expires']=int(t)+e['expiry'] if e['expiry'] else 0;mid=e['mid'];old=pending[c].get(mid)
    if old and (old['qos']!=e['qos'] or old['topic']!=e['topic'] or old['payload']!=e['payload']):pending[c].pop(mid);old=None
    if e['qos']==2:
     if not old:pending[c][mid]=r
    else:route(r,t)
   elif e['type']==6:
    r=pending[c].pop(e['mid'],None)
    if r:route(r,t)
  assert last_mid==131
  print('Final archive message ID:',last_mid)
  fs=[e for e in delivered if e.get('frame',{}).get('valid')];groups=collections.defaultdict(list)
  for e in fs:groups[e['frame']['counter']].append(e)
  print('delivered valid',len(fs),'counters',len(groups),'variants',collections.Counter(len(set(e['frame']['data'] for e in v)) for v in groups.values()))
  pathlib.Path('work/delivered.json').write_text(json.dumps(delivered,indent=2))
  if len(groups)==48 and all(len(set(e['frame']['data'] for e in v))==1 for v in groups.values()):
   blob=b''.join(bytes.fromhex(groups[c][0]['frame']['data']) for c in sorted(groups,key=lambda c:(c-lease['origin'])%65536));s,m=blob[:-32],blob[-32:];key=bytes(a^b for a,b in zip(m,hashlib.sha256(cipher+s).digest()))
   plaintext=AESGCM(key).decrypt(s[:12],s[12:],context+lease['origin'].to_bytes(2,'big'));print('PLAINTEXT',plaintext.decode());pathlib.Path('work/plaintext.json').write_bytes(plaintext)
 finally:
  os.chdir(original_directory)
