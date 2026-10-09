
from __future__ import annotations
from pathlib import Path
from collections import defaultdict,deque,Counter
import re,math,difflib
import numpy as np

ROOT_API=r'(?:Cipher|Signature|KeyAgreement|KeyPairGenerator|KeyFactory|KeyStore|SSLContext)'
ROOT=re.compile(r'\b('+ROOT_API+r')\s*\.\s*(getInstance|getDefault)\s*\(')
IDENT=re.compile(r'\b[A-Za-z_$][\w$]*\b')
STRING=re.compile(r'"(?:\\.|[^"\\])*"')
KEYTYPE=re.compile(r'\b(?:RSA(?:Public|Private|PrivateCrt)Key|EC(?:Public|Private)Key|RSAPublicKeySpec|RSAPrivateKeySpec)\b')
METHOD=re.compile(r'\b(?:public|protected|private|static|final|synchronized)\s+(?:[\w<>\[\],?]+\s+)*([\w$]+)\s*\([^;{}]*\)\s*(?:throws[^{}]+)?\{')
ALG=re.compile(r'RSA|ECDSA|ECDH|SHA\d+with|SunRsaSign|BouncyCastle|\bBC\b')
BOUNDARY=re.compile(r'\b(?:public|protected)\b|\b(?:write|send|save|persist|executeUpdate|put|serialize)\s*\(')

def strip_comments(source):

    token=re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/')
    return token.sub(lambda m:re.sub(r'[^\n]',' ',m[0]) if m[0].startswith(('/',)) else m[0],source)

def scan_project(root,dmax=100.,max_call_edges=3,policy_paths=(),adapter_paths=(),conformance_paths=()):
    if dmax<=0 or not math.isfinite(dmax):raise ValueError('Dmax must be explicit and positive')
    root=Path(root).resolve();nodes={};methods=defaultdict(list);roots=[];edge=defaultdict(set);edge_types={};uncertain=[]
    def link(a,b,kind):
        if a!=b:edge[a].add(b);edge_types[a,b]=kind
    for path in sorted(root.rglob('*.java')):
        if path.is_symlink() or any(p in {'.git','target','build'} for p in path.relative_to(root).parts):continue
        rel=path.relative_to(root).as_posix();text=strip_comments(path.read_text(encoding='utf-8'));imports='java.security' in text or 'javax.crypto' in text or 'javax.net.ssl' in text
        last_def={};scope='<fields>';depth=0;method_depth=None
        fields={}
        for line,code in enumerate(text.splitlines(),1):
            if not code.strip():continue
            m=METHOD.search(code)
            if m:scope=m[1];method_depth=depth;last_def=dict(fields)
            ident=f'{rel}:{line}';words=set(IDENT.findall(STRING.sub('',code)));calls=set(re.findall(r'\b(\w+)\s*\(',STRING.sub('',code)))
            node=dict(id=ident,file=rel,line=line,code=code.strip(),method=scope,words=sorted(words),calls=sorted(calls),boundary=bool(BOUNDARY.search(code)))
            nodes[ident]=node;methods[scope].append(ident)
            for name in words:
                if name in last_def:link(last_def[name],ident,'def-use')

            for name in re.findall(r'\b([\w$]+)\s*\.',STRING.sub('',code)):
                if name in last_def:last_def[name]=ident
            defined=re.findall(r'\b([\w$]+)\s*=(?!=)',code)
            for name in defined:last_def[name]=ident
            if m:
                params=re.search(r'\(([^)]*)\)',code)
                if params:
                    for p in params[1].split(','):
                        w=IDENT.findall(p)
                        if w:last_def[w[-1]]=ident
            if scope=='<fields>':fields.update({k:last_def[k] for k in defined})
            rm=ROOT.search(code)
            if rm and (imports or 'java.security.' in code or 'javax.crypto.' in code):roots.append(dict(id=ident,api=rm[1],confidence='syntactic-import-supported',role='signature' if rm[1]=='Signature' else 'crypto'))
            depth+=STRING.sub('',code).count('{')-STRING.sub('',code).count('}')
            if method_depth is not None and depth<=method_depth:scope='<fields>';method_depth=None;last_def=dict(fields)

    byname=defaultdict(list)
    for ident,n in nodes.items():
        if METHOD.search(n['code']):byname[n['method']].append(ident)
    for ident,n in nodes.items():
        for call in n['calls']:
            entries=byname.get(call,[])
            if len(entries)==1 and entries[0]!=ident:
                entry=entries[0];link(ident,entry,'call')
                for member in methods[call]:
                    if nodes[member]['file']==nodes[entry]['file']:link(entry,member,'method-summary')
            elif len(entries)>1:uncertain.append(dict(node=ident,call=call,reason='ambiguous method name'))
    findings=[];clusters=[];suppressions=[]
    for root_node in roots:
        start=root_node['id'];queue=deque([(start,[start],0)]);paths={}
        while queue:
            item,path,calls=queue.popleft()
            if item in paths:continue
            paths[item]=path
            for nxt in sorted(edge[item]):
                nc=calls+(edge_types[item,nxt]=='call')
                if nc<=max_call_edges:queue.append((nxt,path+[nxt],nc))
        local=[]
        for ident,path in paths.items():
            n=nodes[ident];code=n['code'];rel=n['file'];kinds=[]
            policy=any(rel.startswith(p) for p in policy_paths);adapter=any(rel.startswith(p) for p in adapter_paths);kat=any(rel.startswith(p) for p in conformance_paths)
            if ROOT.search(code) and any(ALG.search(s) for s in STRING.findall(code)):
                kinds+=['AlgLit','Config']
            if KEYTYPE.search(code) and ('public' in code or 'protected' in code or n['method']=='<fields>'):kinds.append('KeyType')
            if re.search(r'new\s+byte\s*\[\s*\d+|(?:length|size\(\))\s*[!=<>]=?\s*\d+|(?:assertEquals|assertArrayEquals)\s*\(\s*\d+',code):kinds.append('SizeAssump')
            if re.search(r'\b(?:write|send|save|persist|serialize)\s*\(',code) and not re.search(r'X509EncodedKeySpec|PKCS8EncodedKeySpec|version|lengthPrefix',code,re.I):kinds.append('Serialize')
            if re.search(r'if\s*\(.*(?:algorithm|suite|RSA|ECDSA)|(?:peer|protocol|header|message).*".*(?:RSA|ECDSA)',code,re.I):kinds.append('Protocol')
            if re.search(r'getInstance\([^)]*,\s*"|new\s+\w*Provider\s*\(|Security.addProvider',code):kinds.append('Provider')
            if ('test' in rel.lower() or 'Test' in n['method']) and re.search(r'assert(?:Equals|ArrayEquals|InstanceOf).*?(?:\d+|\.class|byte)',code):kinds.append('TestOracle')
            for kind in sorted(set(kinds)):
                reason='explicit policy path' if policy and kind in ('AlgLit','Config') else 'explicit adapter path' if adapter and kind in ('KeyType','Provider') else 'explicit conformance-test path' if kat and kind=='TestOracle' else None
                if reason:suppressions.append(dict(root=start,node=ident,smell=kind,reason=reason));continue

                seen=set();todo=list(edge[ident])
                while todo:
                    dep=todo.pop()
                    if dep in seen or dep not in paths:continue
                    seen.add(dep);todo.extend(edge[dep])
                boundary=any(nodes[x]['boundary'] for x in {ident}|seen);fanout=len(seen)
                contribution=(1+math.log2(1+fanout))*(1+.5*int(boundary))
                finding=dict(root=start,node=ident,smell=kind,file=rel,line=n['line'],evidence=code,path=path,fanout=fanout,boundary=boundary,debt=contribution,confidence='bounded syntactic dependency')
                findings.append(finding);local.append(finding)
        clusters.append(dict(root=start,nodes=list(paths),findings=len(local),debt=sum(x['debt'] for x in local)))
    scores=[c['debt'] for c in clusters];cadi=min(100.,100*(float(np.median(scores))+float(np.quantile(scores,.9)))/(2*dmax)) if scores else 0.
    return dict(roots=roots,nodes=list(nodes.values()),edges=[dict(source=a,target=b,kind=edge_types[a,b]) for a in sorted(edge) for b in sorted(edge[a])],findings=findings,clusters=clusters,suppressions=suppressions,unresolved=uncertain,cadi=cadi,dmax=dmax,smell_counts=dict(Counter(x['smell'] for x in findings)),scope='Bounded syntactic Java dependency analysis using source-statement nodes')

RECIPES={
 'AlgLit':('role_factory','automatic only for supported local literal selectors'),
 'Config':('role_factory','automatic only for supported local literal selectors'),
 'KeyType':('generic_key_boundary','assisted: prove no algorithm-specific key methods remain'),
 'SizeAssump':('dynamic_representation_size','assisted: define max bound and peer/storage compatibility'),
 'Serialize':('versioned_crypto_envelope','assisted: choose version and legacy decoder'),
 'Protocol':('capability_negotiation','assisted: explicit suite order and peer policy'),
 'Provider':('provider_adapter','assisted: validate provider behavior'),
 'TestOracle':('semantic_test_oracle','assisted: retain standards/known-answer tests')}
def recipes(report):
    return [dict(root=f['root'],file=f['file'],line=f['line'],smell=f['smell'],recipe=RECIPES[f['smell']][0],guard=RECIPES[f['smell']][1]) for f in report['findings']]

def role_factory_patch(path):

    path=Path(path);original=path.read_text(encoding='utf-8');clean=strip_comments(original)
    if 'CryptoPolicy' in clean:raise ValueError('Existing policy needs manual integration')
    if 'java.security.Signature' not in clean:raise ValueError('Require explicit Signature import')
    pattern=re.compile(r'\bSignature\.getInstance\(\s*"(SHA(?:256|384|512)with(?:RSA|ECDSA))"\s*\)')
    matches=list(pattern.finditer(clean))
    if not matches:raise ValueError('No supported local signature literal')
    algorithms=list(dict.fromkeys(m[1] for m in matches));mapping={a:f'signingSuite{i}' for i,a in enumerate(algorithms)}

    rewritten=original
    for m in reversed(matches):rewritten=rewritten[:m.start()]+f'Signature.getInstance(CryptoPolicy.{mapping[m[1]]}())'+rewritten[m.end():]
    package=re.search(r'^\s*package\s+([\w.]+);',clean,re.M)
    policy=(f'package {package[1]};\n' if package else '')+'final class CryptoPolicy {\n    private CryptoPolicy() {}\n'+''.join(f'    static String {mapping[a]}() {{ return "{a}"; }}\n' for a in algorithms)+'}\n'
    patch=''.join(difflib.unified_diff(original.splitlines(True),rewritten.splitlines(True),fromfile='a/'+path.name,tofile='b/'+path.name))
    patch+=''.join(difflib.unified_diff([],policy.splitlines(True),fromfile='/dev/null',tofile='b/CryptoPolicy.java'))
    return dict(patch=patch,rewritten=rewritten,policy=policy,validation='Source transformation checked; Java build result stored separately',behavior='Algorithm selector preserved')
