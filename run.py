import argparse,json
from pathlib import Path
from cryptodebt import *
from numeric import write_json,environment
def main():
    p=argparse.ArgumentParser();p.add_argument('--root',default='examples/java');p.add_argument('--dmax',type=float,default=100);p.add_argument('--output',default='results');a=p.parse_args()
    out=Path(a.output);out.mkdir(parents=True,exist_ok=True);r=scan_project(a.root,a.dmax);r['environment']=environment();r['refactoring_recipes']=recipes(r);write_json(out/'analysis.json',r)
    local=Path(a.root)/'LocalSigner.java'
    if local.exists():
        patch=role_factory_patch(local);(out/'role_factory.patch').write_text(patch['patch'],encoding='utf-8');write_json(out/'patch_provenance.json',{k:v for k,v in patch.items() if k not in ('rewritten','policy','patch')})
    print(json.dumps(dict(roots=len(r['roots']),findings=len(r['findings']),cadi=r['cadi'],smells=r['smell_counts'])))
if __name__=='__main__':main()
