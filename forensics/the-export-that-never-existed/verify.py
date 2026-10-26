from analyze import *
import exporter
def selected_db(token,solution,name):
 pages=getpages(token);chosen={}
 for pn,bs in pages.items():
  bs=sorted(bs);key=hashlib.sha256(b''.join(bs)).hexdigest();chosen[pn]=[bs[solution['pages'].get(key,0)]]
 return dbimage(chosen,ROOT/(name+'.sqlite'))
class Broker:
 def __init__(self,group,solution,objects,groups):
  self.entries=groups[group];self.solution=solution;self.objects=objects;self.i=0;self.meter=None
 def take(self,route):
  observed,key,offset=self.entries[self.i];assert route==observed,(self.i,route,observed);self.i+=1
  b=self.objects[key][1][int(self.solution['roots'][key])][offset:offset+24];assert len(b)==24;return b
 def finish(self,meter):assert self.i==len(self.entries) and self.meter==meter,(self.i,len(self.entries),self.meter,meter)
def run():
 solution=pickle.loads((ROOT/'solution.pkl').read_bytes());objects=pickle.loads((ROOT/'pack.pkl').read_bytes());groups=pickle.loads((ROOT/'groups.pkl').read_bytes())
 batches=[];district_totals=collections.defaultdict(lambda:[0,0]);details=[]
 for batch in range(4):
  inv=[next(x for x in pub if x[:3]==(204,batch,st)) for st in range(3)]
  dbs=[selected_db(views[(p[3],p[4])][3],solution,f'verify_b{batch}s{st}') for st,p in enumerate(inv)]
  plan=exporter.plan(dbs[0],batch)
  qb=Broker(solution['groups'][batch][0],solution,objects,groups);quote=exporter.quote(dbs[1],plan,qb);qb.finish(inv[1][5])
  rb=Broker(solution['groups'][batch][1],solution,objects,groups);released=exporter.release(dbs[2],quote,rb);rb.finish(inv[2][5]);batches.append(released)
  regions={r[0]:r[2] for r in plan}
  for priority,rank,item,label,billed,data in released:
   region=regions[item];district_totals[region][0]+=1;district_totals[region][1]+=billed
  details.append(dict(batch=batch,planned=len(plan),exported=len(released),quote_group=solution['groups'][batch][0],release_group=solution['groups'][batch][1],quote_meter=qb.meter,release_meter=rb.meter))
 expected={region:[count,amount] for job,region,count,amount in settle if job==204};assert dict(district_totals)==expected,(dict(district_totals),expected)
 output=exporter.serialize(204,batches);digest=hashlib.sha256(output).hexdigest();flag='isfcr{'+digest+'}'
 out=Path(os.environ['DISPATCH_OUTPUT']);out.mkdir(exist_ok=True);(out/'job-204.bin').write_bytes(output);(out/'flag.txt').write_text(flag+'\n')
 (out/'verification.json').write_text(json.dumps(dict(flag=flag,bytes=len(output),batches=details,settlement=expected),indent=2))
 print(flag);print('bytes',len(output),'rows',sum(map(len,batches)));print(json.dumps(details))
if __name__=='__main__':run()
