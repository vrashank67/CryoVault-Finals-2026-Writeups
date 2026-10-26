"""Recover export R-184; optional argument is the supplied bundle directory."""
import pathlib
import subprocess
import sys

root=pathlib.Path(__file__).resolve().parent
for name in ('inspect.py','analyze.py','recover_messages.py'):
    args=[sys.executable,str(root/name)]
    if name=='inspect.py' and len(sys.argv)>1:args.append(sys.argv[1])
    subprocess.run(args,check=True)
subprocess.run(['node',str(root/'replay.cjs')],check=True)
