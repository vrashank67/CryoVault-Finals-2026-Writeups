import json,pathlib,collections,struct
R=pathlib.Path(__file__).resolve().parent
events=json.loads((R/'events.json').read_text())
streams=collections.defaultdict(list)
for e in events: streams[e['stream']].append(e)
ordered=[]
for stream,items in streams.items():
    byprev={e['previous']:e for e in items}
    assert len(byprev)==len(items)
    heads=[e for e in items if e['previous'] not in {x['id'] for x in items}]
    print('STREAM',stream,'records',len(items),'profiles',dict(collections.Counter(e['profile'] for e in items)),'heads',len(heads))
    chain=[]
    for e in heads:
        while e:
            chain.append(e)
            e=byprev.get(e['id'])
    assert len(chain)==len(items)
    ordered.append({'stream':stream,'events':chain})
    print('FIRST', [e['event'] for e in chain[:20]])
    print('SPECIAL',[(i,e['event']) for i,e in enumerate(chain) if e['event'][0] in [1,7,48,49,50,63]])
(R/'ordered.json').write_text(json.dumps(ordered,indent=2))
for p in sorted((R/'evidence/profiles').glob('*/review.db-wal')):
    b=p.read_bytes();ps=struct.unpack_from('>I',b,8)[0]
    frames=(len(b)-32)//(ps+24)
    print('WAL',p.parent.name,len(b),'page',ps,'frames',frames)
    print('FRAME HEADERS',[struct.unpack_from('>II',b,32+i*(ps+24)) for i in range(min(25,frames))])
