from analyze import *
def table(pages,root):
 out={}
 for pn in tablepages(pages,root):
  for b in pages[pn]:
   for rid,row in cells(b,pn):out.setdefault(rid,[]).append(row)
 return out
def run(job=204):
 groups=pickle.loads((ROOT/'groups.pkl').read_bytes());objects=pickle.loads((ROOT/'pack.pkl').read_bytes())
 fixed=collections.Counter();uncertain=[];batch_fixed=[0]*4
 for batch in range(4):
  pages=[]
  for stage in range(3):
   p=next(x for x in pub if x[:3]==(job,batch,stage));pages.append(getpages(views[(p[3],p[4])][3]))
  manifest=table(pages[0],2)
  plan=sorted(((rid,rs[0]) for rid,rs in manifest.items() if rs[0][1]==batch and rs[0][7]),key=lambda x:(x[1][6],x[0]))
  tariff=table(pages[1],3);district=table(pages[1],4);clearance=table(pages[2],5)
  for i,(rid,row) in enumerate(plan):
   mixes=[]
   for g,deliveries in groups.items():
    if len(deliveries)!=len(plan):continue
    _,key,offset=deliveries[i]
    for b in objects[key][1]:mixes.append(int.from_bytes(b[offset:offset+2],'little')+3*b[offset+2]+17*b[offset+3])
   region=row[3];bases=[((row[4]*t[1]-t[2])*t[3])//d[2]+d[1] for t in tariff[rid] for d in district[region]]
   enabled,ceiling=clearance[rid][0][1:3];lower=min(bases)+min(mixes);upper=max(bases)+max(mixes)
   if enabled and upper<=ceiling:fixed[region]+=1;batch_fixed[batch]+=1
   if enabled and lower<=ceiling<upper:uncertain.append((batch,rid,region))
 desired={region:count-fixed[region] for j,region,count,total in settle if j==job};valid=[]
 for bits in itertools.product(range(2),repeat=len(uncertain)):
  counts=collections.Counter(region for (_,_,region),bit in zip(uncertain,bits) if bit)
  if all(counts[region]==count for region,count in desired.items()):valid.append(bits)
 assert valid
 forced={(batch,rid):next(iter(values)) for i,(batch,rid,region) in enumerate(uncertain) if len(values:={bits[i] for bits in valid})==1}
 releasecounts={tuple(batch_fixed[batch]+sum(bit for (b,_,_),bit in zip(uncertain,bits) if b==batch) for batch in range(4)) for bits in valid}
 assert len(releasecounts)==1
 counts=next(iter(releasecounts));(ROOT/'eligibility.pkl').write_bytes(pickle.dumps(forced));(ROOT/'releasecounts.pkl').write_bytes(pickle.dumps(counts))
 print('settlement eligibility patterns',len(valid),'release counts',counts,flush=True)
 return forced,counts
if __name__=='__main__':run()
