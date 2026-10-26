#!/usr/bin/env python3
"""Run on Linux x86-64 against an extracted, original incident bundle."""
from pathlib import Path
import argparse,gzip,shutil,subprocess,tempfile,os,json
parser=argparse.ArgumentParser()
parser.add_argument('bundle',type=Path,help='Directory containing rootfs/ and incident/')
parser.add_argument('--output',type=Path,default=Path('recovered'))
args=parser.parse_args();bundle=args.bundle.resolve();output=args.output.resolve()
source=Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix='frozen-ledger-') as tmp:
 root=Path(tmp);work=root/'work';work.mkdir()
 for name in ['coremem.py','hprof.py','SA.java','run_sa.py','snapshots.py','recover.py','verify_native.py']:
  shutil.copyfile(source/name,work/name)
 (work/'rootfs').symlink_to(bundle/'rootfs',target_is_directory=True)
 with gzip.open(bundle/'incident/core.gz','rb') as src,(work/'core').open('wb') as dst:shutil.copyfileobj(src,dst)
 rt=work/'rootfs/srv/ledger/runtime';env=os.environ.copy();env['SA_ALTROOT']=str(work/'rootfs')
 subprocess.run([str(rt/'bin/jhsdb'),'jmap','--binaryheap','--dumpfile',str(work/'heap.hprof'),'--exe',str(rt/'bin/java'),'--core',str(work/'core')],env=env,cwd=work,check=True)
 subprocess.run(['python3','hprof.py'],cwd=work,check=True)
 import sys
 sys.path.insert(0,str(work));from coremem import Core
 core=Core();objects=json.loads((work/'objects.json').read_text())
 (work/'chunks.txt').write_text('\n'.join(hex(o['tail'])+' '+str(56+core.u32(o['tail']+12)*8) for o in objects if o.get('tail')))
 core.d.close();core.f.close()
 for name in ['run_sa.py','snapshots.py','recover.py','verify_native.py']:
  subprocess.run(['python3',name],cwd=work,check=True)
 output.mkdir(parents=True,exist_ok=True)
 for name in ['closing.fld','flag.txt']:shutil.copyfile(root/'outputs'/name,output/name)
 print((output/'flag.txt').read_text().strip())
