"""Dispatch export module, revision 9. Author: sr."""
import struct
BATCHES=4

def plan(db,batch):
    return db.execute('''SELECT id,label,region,units,slot,rank FROM manifest
                         WHERE batch=? AND enabled=1 ORDER BY rank,id''',(batch,)).fetchall()

def quote_seed(rows):return (13*len(rows)+sum(r[0] for r in rows))%65521

def quote_route(item,slot,rate,fee,state):return (slot+16*rate+256*fee+11*item+state)%13

def quote_mix(data):return int.from_bytes(data[:2],'little')+3*data[2]+17*data[3]

def quote_next(state,item,amount,data):return (31*state+data[4]+17*data[5]+item+amount)%65521

def quote(db,rows,broker):
    out=[];state=quote_seed(rows)
    for item,label,region,units,slot,rank in rows:
        rate,discount,basis=db.execute('SELECT rate,discount,basis FROM tariff WHERE id=?',(item,)).fetchone()
        fee,divisor=db.execute('SELECT fee,divisor FROM district WHERE id=?',(region,)).fetchone()
        data=broker.take(quote_route(item,slot,rate,fee,state))
        if len(data)!=24:raise ValueError('short delivery')
        amount=((units*rate-discount)*basis)//divisor+fee+quote_mix(data)
        out.append((item,label,region,slot,rank,amount,data));state=quote_next(state,item,amount,data)
    broker.meter=state
    return out

def release_seed(rows):return (7*len(rows)+sum(r[5] for r in rows))%65521

def release_route(item,priority,amount,state):return (19*item+37*priority+17*amount+state)%13

def stamp_mix(stamp):return int.from_bytes(stamp[12:14],'little')

def release_next(state,billed,stamp):return (43*state+stamp[15]+11*stamp[16]+billed)%65521

def release(db,rows,broker):
    out=[];state=release_seed(rows)
    for item,label,region,slot,rank,amount,data in rows:
        enabled,ceiling,priority,surcharge=db.execute('SELECT enabled,ceiling,priority,surcharge FROM clearance WHERE id=?',(item,)).fetchone()
        if enabled and amount<=ceiling:
            stamp=broker.take(release_route(item,priority,amount,state))
            if len(stamp)!=24:raise ValueError('short approval stamp')
            billed=amount+surcharge+stamp_mix(stamp)
            out.append((priority,rank,item,label,billed,data[:12]+stamp[12:]));state=release_next(state,billed,stamp)
    broker.meter=state
    return sorted(out,key=lambda r:(r[0],r[1],r[2]))

def serialize(job,batches):
    out=bytearray(b'DSP9\x00'+struct.pack('<IH',job,BATCHES))
    for batch,rows in enumerate(batches):
        out+=struct.pack('<HH',batch,len(rows))
        for priority,rank,item,label,amount,data in rows:
            label=label.encode('utf-8');out+=struct.pack('<IiiqH',item,priority,rank,amount,len(label))+label+data
    return bytes(out)
