#!/usr/bin/env python3
"""Reproduce job 204 from the original capture, or rerun the finite constraint search."""
import argparse,hashlib,json,os,pickle
from pathlib import Path

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('archive',type=Path,help='dispatch.capture or its containing directory')
 p.add_argument('--work',type=Path,default=Path('work/export204-reproduction'))
 p.add_argument('--out',type=Path,default=Path('outputs/reproduced-export204'))
 p.add_argument('--search',action='store_true',help='rediscover selections with OR-Tools instead of using the verified certificate')
 p.add_argument('--seconds',type=int,default=600)
 a=p.parse_args();archive=a.archive/'dispatch.capture' if a.archive.is_dir() else a.archive
 assert hashlib.sha256(archive.read_bytes()).hexdigest()=='87b817b1653a47ed8c6ce7aafcd6ed571382b62cdcfbc22a8dcfbf68cf4feda2','unexpected archive'
 a.work.mkdir(parents=True,exist_ok=True);a.out.mkdir(parents=True,exist_ok=True)
 os.environ.update(DISPATCH_INPUT=str(archive.resolve().parent),DISPATCH_WORK=str(a.work.resolve()),DISPATCH_OUTPUT=str(a.out.resolve()),DISPATCH_SECONDS=str(a.seconds))
 import recover
 if not (a.work/'chains.pkl').exists():recover.walchains()
 import pack
 objects=pack.decode();groups=pack.replay(objects);(a.work/'groups.pkl').write_bytes(pickle.dumps(groups))
 import bounds
 bounds.run()
 if a.search:
  import solve_cp
  solve_cp.run()
  assert (a.work/'solution.pkl').exists(),'constraint search did not finish with a solution'
 else:
  selection=json.loads((Path(__file__).parent/'selection.json').read_text())
  (a.work/'solution.pkl').write_bytes(pickle.dumps(selection))
 import verify
 verify.run()
 assert hashlib.sha256((a.out/'job-204.bin').read_bytes()).hexdigest()=='c916c4f7b8ecccf073bf5cd6e815218f3622ba7c3500919f2a6b11f2db891b68'

if __name__=='__main__':main()
