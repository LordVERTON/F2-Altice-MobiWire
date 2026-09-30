import json
import sys
from inspect_alice_details import ROOT,load
from match_alice_callees import Matcher,calls,target,summary

q,a=load('qmobile_normalized'),load('altice')
m=Matcher(q,a)
result={}
for entry in sys.argv[1:]:
    if entry not in q: continue
    f=q[entry]
    best=m.best(entry,5)
    result[entry]=dict(summary=summary(f),best=best,callees=[target(i) for i in calls(f)])
    print(summary(f), 'calls',result[entry]['callees'])
    print([(r['altice'],r['score'],r['q_ins'],r['a_ins'],r['q_calls'],r['a_calls']) for r in best])
(ROOT/'extra_target_matches.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
