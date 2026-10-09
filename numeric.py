
from __future__ import annotations
import json, math, platform, sys
from pathlib import Path
import numpy as np
from scipy import stats

def probability(p):
    p = np.asarray(p, dtype=float)
    if p.ndim != 1 or not len(p) or not np.isfinite(p).all() or (p < 0).any() or not np.isclose(p.sum(), 1, atol=1e-10, rtol=0):
        raise ValueError('Expected a finite nonnegative probability vector summing to one')
    return p

def tvd(p, q):
    p, q = probability(p), probability(q)
    if p.shape != q.shape: raise ValueError('Distribution dimensions differ')
    return float(np.abs(p-q).sum()/2)

def binomial_interval(k, n, alpha=.05):
    if not 0 < alpha < 1 or not isinstance(n, (int, np.integer)) or not 0 <= k <= n or n <= 0:
        raise ValueError('Invalid binomial interval arguments')
    return (0. if k == 0 else float(stats.beta.ppf(alpha/2, k, n-k+1)),
            1. if k == n else float(stats.beta.ppf(1-alpha/2, k+1, n-k)))

def wilson(k, n, alpha=.05):
    if n <= 0: return [None, None]
    z=stats.norm.ppf(1-alpha/2); p=k/n; d=1+z*z/n
    c=(p+z*z/(2*n))/d; h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return [float(c-h),float(c+h)]

def holm(pvalues, alpha=.05):
    p=np.asarray(pvalues,dtype=float)
    if not np.isfinite(p).all() or ((p<0)|(p>1)).any(): raise ValueError('Invalid p values')
    order=np.argsort(p); adj=np.ones(len(p)); running=0.
    for rank,i in enumerate(order):
        running=max(running, float(p[i])*(len(p)-rank)); adj[i]=min(1.,running)
    return adj.tolist(), (adj<=alpha).tolist()

def write_json(path, data):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    def convert(x):
        if isinstance(x,np.ndarray): return x.tolist()
        if isinstance(x,np.generic): return x.item()
        raise TypeError(type(x).__name__)
    path.write_text(json.dumps(data,indent=2,ensure_ascii=False,default=convert,allow_nan=False)+'\n',encoding='utf-8')

def environment():
    import scipy
    return dict(python=sys.version,platform=platform.platform(),numpy=np.__version__,scipy=scipy.__version__)

def statevector(n, gates):

    if type(n) is not int or not 1 <= n <= 16: raise ValueError('Simulator supports 1..16 qubits')
    v=np.zeros(1<<n,dtype=complex); v[0]=1
    for gate in gates:
        name=gate[0].upper(); q=int(gate[1])
        if not 0<=q<n: raise ValueError('Invalid wire')
        if name in ('CX','CZ'):
            t=int(gate[2])
            if t==q or not 0<=t<n: raise ValueError('Invalid controlled gate')
            for i in range(1<<n):
                if (i>>q)&1:
                    if name=='CZ' and (i>>t)&1: v[i]*=-1
                    if name=='CX' and not (i>>t)&1:
                        j=i|(1<<t); v[i],v[j]=v[j],v[i]
            continue
        if name=='H': m=np.array([[1,1],[1,-1]])/math.sqrt(2)
        elif name=='X': m=np.array([[0,1],[1,0]])
        elif name=='Z': m=np.diag([1,-1])
        elif name=='S': m=np.diag([1,1j])
        elif name=='T': m=np.diag([1,np.exp(1j*np.pi/4)])
        elif name=='RY':
            a=gate[2]/2; m=np.array([[np.cos(a),-np.sin(a)],[np.sin(a),np.cos(a)]])
        elif name=='RZ': m=np.diag([np.exp(-1j*gate[2]/2),np.exp(1j*gate[2]/2)])
        else: raise ValueError('Unsupported gate: '+name)
        for i in range(1<<n):
            if not (i>>q)&1:
                j=i|(1<<q); v[i],v[j]=m @ np.array([v[i],v[j]])
    if not np.isclose(np.vdot(v,v).real,1,atol=1e-10): raise ArithmeticError('State norm lost')
    return v

def circuit_probabilities(n,gates):
    p=np.abs(statevector(n,gates))**2
    return p/p.sum()

def circuit_family(family,n,rng):

    g=[]
    if family=='GHZ':
        g=[('RY',0,float(rng.uniform(.7,2.4)))]+[('CX',i,i+1) for i in range(n-1)]
    elif family=='W-like':
        g=[('RY',i,float(2*np.arcsin(1/np.sqrt(n-i)))) for i in range(n)]
        g += [('CX',i,i+1) for i in range(n-1)]
    elif family=='QFT-like':
        for i in range(n):
            g += [('RY',i,float(rng.uniform(.2,2.5))),('H',i),('RZ',i,float(np.pi/(i+1)))]
            if i+1<n:g += [('CZ',i,i+1)]
        g += [('H',i) for i in range(n)]
    elif family=='Grover-like':
        g=[('H',i) for i in range(n)]
        for _ in range(2):
            g += [('CZ',i,i+1) for i in range(n-1)]
            g += [('RY',i,float(rng.uniform(.2,1.4))) for i in range(n)]
            g += [('H',i) for i in range(n)]
    elif family in ('Random','Variational'):
        for _ in range(2 if family=='Variational' else 3):
            for i in range(n):g += [('RY',i,float(rng.uniform(-np.pi,np.pi))),('RZ',i,float(rng.uniform(-np.pi,np.pi)))]
            g += [('CX',i,i+1) for i in range(n-1)]
    else:raise ValueError(family)
    return g

def noise(p,n,depth,g,e):
    if g<0 or not 0<=e<=1: raise ValueError('Invalid noise')
    p=probability(p).copy(); lam=1-np.exp(-g*depth); p=(1-lam)*p+lam/len(p)
    indices=np.arange(len(p))
    for q in range(n):p=(1-e)*p+e*p[indices^(1<<q)]
    return p/p.sum()
