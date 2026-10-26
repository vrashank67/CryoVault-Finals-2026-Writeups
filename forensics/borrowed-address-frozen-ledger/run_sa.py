from pathlib import Path
import subprocess,os,sys
b=Path(__file__).resolve().parent;os.chdir(b)
rt=b/'rootfs/srv/ledger/runtime'
env=os.environ.copy();env['SA_ALTROOT']=str(b/'rootfs')
opts=['--add-modules','jdk.hotspot.agent']
for p in ['tools','runtime','runtime.amd64','code','oops','debugger','types','memory','utilities','classfile']:
 opts+=['--add-exports',f'jdk.hotspot.agent/sun.jvm.hotspot.{p}=ALL-UNNAMED']
subprocess.run([str(rt/'bin/javac'),*opts,'SA.java'],check=True)
with open('sa.log','w') as f:subprocess.run([str(rt/'bin/java'),*opts,'SA',str(rt/'bin/java'),str(b/'core'),*sys.argv[1:]],env=env,stdout=f,stderr=subprocess.STDOUT)
print(Path('sa.log').read_text())
