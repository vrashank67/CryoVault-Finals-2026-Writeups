from analyze import *
sys.path.insert(0,str(ROOT/'deps'))
try:
 import pandas
except ImportError:
 # The model uses no pandas convenience API; provide annotation types only.
 import types
 pandas=types.ModuleType('pandas')
 class UnusedPandasType:
  def __init__(self,*a,**kw):raise RuntimeError('pandas convenience API is unavailable')
 pandas.Index=type('Index',(UnusedPandasType,),{})
 pandas.Series=type('Series',(UnusedPandasType,),{})
 sys.modules['pandas']=pandas
from ortools.sat.python import cp_model as cp
import time
objects=pickle.loads((ROOT/'pack.pkl').read_bytes());groups=pickle.loads((ROOT/'groups.pkl').read_bytes())
M=cp.CpModel();pagevars={};rootvars={};batchinfo=[];groupvars=[]
forced=pickle.loads((ROOT/'eligibility.pkl').read_bytes());releasecounts=pickle.loads((ROOT/'releasecounts.pkl').read_bytes())
def intvar(name,lo,hi):return M.NewIntVar(int(lo),int(hi),name)
def element(index,values,name):
 out=intvar(name,min(values),max(values));M.AddElement(index,values,out);return out
class Val:
 def __init__(self,idx,values,name):
  self.idx=idx;self.values=values;self.v=element(idx,values,name) if len(set(values))>1 else values[0]
 def map(self,fn,name):return element(self.idx,[fn(x) for x in self.values],name)
def table(pages,root,col):
 out={}
 for pn in tablepages(pages,root):
  bs=sorted(pages[pn]);variants=[cells(b,pn) for b in bs];key=hashlib.sha256(b''.join(bs)).hexdigest()
  if key not in pagevars:pagevars[key]=intvar('page_'+key[:16],0,len(bs)-1)
  idx=pagevars[key]
  for i,(rid,row) in enumerate(variants[0]):
   row=row.copy();row[0]=rid;row[col]=Val(idx,[rs[i][1][col] for rs in variants],f't{root}_p{key[:8]}_r{rid}');out[rid]=row
 return out
def root(key):
 if key not in rootvars:rootvars[key]=M.NewBoolVar('root_'+key.replace(':','_'))
 return rootvars[key]
def delivery(name,candidates,stage,n):
 choice=intvar(name+'_choice',0,len(candidates)-1);gid=element(choice,candidates,name+'_group');groupvars.append(gid)
 length=element(choice,[len(groups[g]) for g in candidates],name+'_length');out=[]
 for i in range(n):
  routes=[];mixes=[];adds=[];roots=[]
  for g in candidates:
   if i>=len(groups[g]):routes.append(0);mixes.extend([0,0]);adds.extend([0,0]);roots.append(0);continue
   route,key,offset=groups[g][i];data=[b[offset:offset+24] for b in objects[key][1]];routes.append(route);roots.append(root(key))
   if stage==1:
    mixes.extend(int.from_bytes(b[:2],'little')+3*b[2]+17*b[3] for b in data);adds.extend(b[4]+17*b[5] for b in data)
   else:mixes.extend(int.from_bytes(b[12:14],'little') for b in data);adds.extend(b[15]+11*b[16] for b in data)
  rv=M.NewBoolVar(f'{name}_root_{i}');M.AddElement(choice,roots,rv)
  ix=intvar(f'{name}_index_{i}',0,2*len(candidates)-1);M.Add(ix==2*choice+rv)
  out.append((element(choice,routes,f'{name}_route_{i}'),element(ix,mixes,f'{name}_mix_{i}'),element(ix,adds,f'{name}_add_{i}')))
 return gid,length,out
def state(name,expr,maxwrap=100):
 st=intvar(name,0,65520);wrap=intvar(name+'_wrap',-maxwrap,maxwrap);M.Add(st==expr-65521*wrap);return st
def route_constraint(expr,route,name,lo=-1000000,hi=1000000,enable=None):
 k=intvar(name+'_div13',lo,hi);c=M.Add(expr==route+13*k)
 if enable is not None:c.OnlyEnforceIf(enable)
def build(job=204):
 for batch in range(4):
  pages=[];meters=[]
  for stage in range(3):
   p=next(x for x in pub if x[:3]==(job,batch,stage));pages.append(getpages(views[(p[3],p[4])][3]));meters.append(p[5])
  ma=table(pages[0],2,5);ta=table(pages[1],3,1);di=table(pages[1],4,1);cl=table(pages[2],5,3)
  plans=sorted((r for r in ma.values() if r[1]==batch and r[7]),key=lambda r:(r[6],r[0]));n=len(plans)
  qc=[g for g,ds in groups.items() if len(ds)==n];qg,ql,qd=delivery(f'b{batch}q',qc,1,n)
  qs=(13*n+sum(r[0] for r in plans))%65521;quoted=[];mincount=maxcount=0
  for i,row in enumerate(plans):
   item,_,label,region,units,slot,rank,_,_=row;_,rate,discount,basis,_=ta[item];_,fee,divisor,_=di[region]
   bases=[((units*r-discount)*basis)//divisor+f for r in rate.values for f in fee.values];mixes=[]
   for g in qc:
    _,key,off=groups[g][i]
    for b in objects[key][1]:mixes.append(int.from_bytes(b[off:off+2],'little')+3*b[off+2]+17*b[off+3])
   lower=min(bases)+min(mixes);upper=max(bases)+max(mixes)
   amount=intvar(f'b{batch}_amount_{i}',lower,upper);base=rate.map(lambda r:((units*r-discount)*basis)//divisor,f'b{batch}_base_{i}')
   M.Add(amount==base+fee.v+qd[i][1]);route_constraint(slot.v+16*rate.v+256*fee.v+11*item+qs,qd[i][0],f'b{batch}_qroute_{i}')
   qs=state(f'b{batch}_qs_{i}',31*qs+qd[i][2]+item+amount)
   _,enabled,ceiling,priority,surcharge,_=cl[item]
   eligible=M.NewBoolVar(f'b{batch}_eligible_{i}')
   if not enabled or lower>ceiling:M.Add(eligible==0)
   elif upper<=ceiling:M.Add(eligible==1);mincount+=1;maxcount+=1
   else:M.Add(amount<=ceiling).OnlyEnforceIf(eligible);M.Add(amount>ceiling).OnlyEnforceIf(eligible.Not());maxcount+=1
   if (batch,item) in forced:M.Add(eligible==forced[(batch,item)])
   quoted.append(dict(item=item,label=label,region=region,slot=slot.v,rank=rank,amount=amount,priority=priority.v,surcharge=surcharge,eligible=eligible,lower=lower,upper=upper))
  M.Add(qs==meters[1]);rc=[g for g,ds in groups.items() if len(ds)==releasecounts[batch]];maxcount=releasecounts[batch];rg,rl,rd=delivery(f'b{batch}r',rc,2,maxcount)
  seed=7*n+sum(q['amount'] for q in quoted);rs=state(f'b{batch}_rseed',seed);ci=0
  for i,q in enumerate(quoted):
   route=intvar(f'b{batch}_rroute_{i}',0,12);mix=intvar(f'b{batch}_rmix_{i}',0,65535);add=intvar(f'b{batch}_radd_{i}',0,3060)
   M.AddElement(ci,[d[0] for d in rd]+[0],route);M.AddElement(ci,[d[1] for d in rd]+[0],mix);M.AddElement(ci,[d[2] for d in rd]+[0],add)
   route_constraint(19*q['item']+37*q['priority']+17*q['amount']+rs,route,f'b{batch}_rrouteeq_{i}',-5000000,5000000,q['eligible'])
   billed=intvar(f'b{batch}_billed_{i}',min(0,q['lower']+q['surcharge']),q['upper']+q['surcharge']+65535)
   M.Add(billed==q['amount']+q['surcharge']+mix).OnlyEnforceIf(q['eligible']);M.Add(billed==0).OnlyEnforceIf(q['eligible'].Not());q['billed']=billed
   st=intvar(f'b{batch}_rs_{i}',0,65520);wrap=intvar(f'b{batch}_rswrap_{i}',-100,100)
   M.Add(st==43*rs+add+billed-65521*wrap).OnlyEnforceIf(q['eligible']);M.Add(st==rs).OnlyEnforceIf(q['eligible'].Not());rs=st
   ci2=intvar(f'b{batch}_consumed_{i}',0,maxcount);M.Add(ci2==ci+q['eligible']);ci=ci2
  M.Add(rs==meters[2]);M.Add(ci==rl);batchinfo.append((plans,quoted,qg,rg))
  print('built batch',batch,'quote candidates',len(qc),'release candidates',len(rc),flush=True)
 M.AddAllDifferent(groupvars)
 for j,region,count,total in settle:
  if j!=job:continue
  rows=[q for _,qs,_,_ in batchinfo for q in qs if q['region']==region]
  M.Add(sum(q['eligible'] for q in rows)==count);M.Add(sum(q['billed'] for q in rows)==total)
def run():
 build();M.ExportToFile(str(ROOT/'model_cp.pbtxt'));S=cp.CpSolver();S.parameters.max_time_in_seconds=int(os.environ.get('DISPATCH_SECONDS',600));S.parameters.num_search_workers=8;S.parameters.log_search_progress=True
 print('valid',M.Validate(),flush=True);start=time.time();result=S.Solve(M);print('result',S.StatusName(result),'time',time.time()-start,flush=True)
 if result in (cp.OPTIMAL,cp.FEASIBLE):
  answer=dict(pages={k:S.Value(v) for k,v in pagevars.items()},roots={k:bool(S.Value(v)) for k,v in rootvars.items()},groups=[(S.Value(qg),S.Value(rg)) for _,_,qg,rg in batchinfo])
  print(answer['groups'],flush=True);(ROOT/'solution.pkl').write_bytes(pickle.dumps(answer))
if __name__=='__main__':run()
