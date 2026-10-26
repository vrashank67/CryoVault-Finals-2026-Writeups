from pathlib import Path
from PIL import Image,ImageDraw,ImageFont
import numpy as np,cv2,json
cv2.setNumThreads(1)
import argparse
p=argparse.ArgumentParser();p.add_argument('charts',type=Path);p.add_argument('--output',type=Path,default=Path('ring_candidates.json'));args=p.parse_args();root=args.charts;hits=[]
for f in sorted(root.glob('*.png')):
 a=np.array(Image.open(f).convert('L'));inv=(255-a)
 contours,_=cv2.findContours(inv,cv2.RETR_LIST,cv2.CHAIN_APPROX_SIMPLE)
 best=[]
 for c in contours:
  x,y,w,h=cv2.boundingRect(c);area=cv2.contourArea(c)
  if not(28<=w<=150 and 28<=h<=120 and .55<w/h<1.8 and area>450):continue
  per=cv2.arcLength(c,True);circularity=4*np.pi*area/per**2
  if circularity>.60:best.append(dict(box=[int(x),int(y),int(w),int(h)],area=area,circ=circularity))
 if best:hits.append(dict(file=f.name,candidates=best))
print('candidate sheets',len(hits));print(json.dumps(hits[:30],indent=1));args.output.write_text(json.dumps(hits,indent=2))
