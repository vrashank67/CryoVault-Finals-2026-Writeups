import pathlib,subprocess,re,tempfile,json,os,hashlib,hmac,sys,tarfile
inputs=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else '.').resolve()
base=pathlib.Path(tempfile.mkdtemp(prefix='permafrost-input-'))
subprocess.run(['git','clone',str(inputs/'vault-deployer.bundle'),str(base/'repo')],check=True,capture_output=True)
with tarfile.open(inputs/'floe-logs.tar.gz') as archive:
    archive.extractall(base,filter='data')
root=pathlib.Path(tempfile.mkdtemp(prefix='replay-',dir=base))
def git(w,*args):
    return subprocess.check_output(['git','-C',str(w),*args],stderr=subprocess.DEVNULL).decode().strip()
logs=[]
for p in (base/'floe-logs').rglob('*deploy.log'):
    t=p.read_text(encoding='utf8');logs.append((t[:24],t,p))
index=json.loads((inputs/'floe-cache-index.json').read_text())
key=bytearray(32); records=[]; workers={}
for _,t,p in sorted(logs):
    seq=int(re.search(r'FLOE_PIPELINE_SEQ=(\d+)',t)[1])
    host=re.search(r'host (\S+)',t)[1]
    if 'Initialized empty Git repository' in t or host not in workers:
        workers[host]=root/f'{host}-{seq}'
    w=workers[host]
    if not w.exists():
        w.mkdir();git(w,'init');git(w,'remote','add','origin',(base/'repo').as_uri())
    git(w,'config','core.autocrlf',re.search(r'core.autocrlf=(\w+)',t)[1])
    commit=re.search(r'git fetch --no-tags --depth=20 origin ([a-f0-9]{40})',t)[1]
    git(w,'fetch','--no-tags','--depth=20','origin',commit)
    git(w,'checkout','--force',commit)
    git(w,'clean','-ffdx')
    env=os.environ.copy();env['DEPLOY_KEY']='00'*32;env['FLOE_PIPELINE_SEQ']=str(seq);env['FLOE_ENVIRONMENT']='hallb'
    env['PYTHONUTF8']='1' if 'PYTHONUTF8=1' in t else '0'
    result=subprocess.run(['python','-c','import ci.cachekey as c;print(c.config_digest().hex())'],cwd=w,env=env,capture_output=True,text=True)
    if 'saved .signed' not in t: continue
    stamp=re.search(r'(2026-\S+) .*saved \.signed',t)[1]
    entry=next((e for e in index['entries'] if e['key'].startswith('deploy-') and e['created_at'][:19]==stamp[:19]),None)
    if entry:
        digest=bytes.fromhex(result.stdout.strip());tag=bytes.fromhex(entry['key'].split('-')[-1]);pad=bytes(a^b for a,b in zip(digest,tag));key[seq%4::4]=pad
        rec=dict(seq=seq,host=host,digest=digest.hex(),tag=tag.hex(),pad=pad.hex(),crlf=[(str(f.relative_to(w)),f.read_bytes().count(b'\r\n')) for f in (w/'config').rglob('*') if f.is_file()]);records.append(rec)
        print(json.dumps(rec),flush=True)
    if seq==281:
        count=git(w,'rev-list','--count','HEAD');lineage=hashlib.sha256(git(w,'rev-list','HEAD').encode()).hexdigest()[:16]
        msg='\n'.join(['vault-deployer','hallb/281',commit,count,lineage]).encode()
        n=int.from_bytes(hmac.new(key,msg,hashlib.sha256).digest(),'big');a='ABCDEFGHJKMNPQRSTUVWXYZ23456789';out=''
        for _ in range(12): n,r=divmod(n,len(a));out+=a[r]
        auth='FL-'+'-'.join(out[i:i+4] for i in (0,4,8))
        env['DEPLOY_KEY']=key.hex()
        actual=subprocess.check_output(['python','ci/sign_release.py'],cwd=w,env=env,text=True)
        assert 'authorisation '+auth in actual
        print('KEY',key.hex(),'COUNT',count,'LINEAGE',lineage,'AUTH',auth,flush=True)
        print('Original signer executable:',actual.strip(),flush=True)
        (base/'replay-result.json').write_text(json.dumps(dict(key=key.hex(),count=count,lineage=lineage,auth=auth,records=records,root=str(root)),indent=2))
