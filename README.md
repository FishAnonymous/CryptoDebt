# CryptoDebt

Eight-category crypto-agility smell detection for Java, with dependency paths, debt scores and refactoring output.

## Files

| Item | Definition |
|---|---|
| cryptodebt.py | Dependency analysis, rules, scoring and patch generation |
| examples/java | Detection and refactoring fixtures |
| run.py | Analysis and role-factory extraction entry point |

## Environment and execution

Python 3.11 or newer is required. Dependency constraints are listed in `requirements.txt`. Versions used for validation are recorded in `requirements-tested.txt`.

```text
python -m pip install -r requirements.txt
python run.py
python run_tests.py
python run.py --root examples/java --dmax 100 --output results/rescan
```

## Parameters and methods

| Item | Definition |
|---|---|
| Rules | AlgLit, KeyType, SizeAssump, Serialize, Protocol, Provider, Config and TestOracle |
| Dependency nodes | Source statements |
| Dependency edges | Definition/use, receiver calls and uniquely named local methods |
| Call expansion | At most three ordinary call edges |
| D(t) | sum((1+log2(1+fanout))*(1+0.5*boundary)) |
| CADI | Normalized median and 90th percentile of root scores; example Dmax=100 |
| Suppressor configuration | policy_paths, adapter_paths and conformance_paths |
| Automatic refactoring | Role-factory extraction preserving the algorithm selector |

Each finding records its root, category, location, evidence path, fan-out, boundary indicator and score. Dmax is an explicit parameter. Role-factory extraction produces a span-based unified diff and leaves the input source file unchanged.

## Implementation scope and data

The front end uses line-oriented lexical analysis and bounded syntactic dependencies. Type resolution and context-sensitive inter-module data flow are not included. Other refactoring recipes return preconditions and assisted status. The package includes generated Java fixtures. External corpora, manual annotations and developer migration-time datasets are not bundled.

Examples and controlled benchmarks are produced by the included generators.

## Outputs and validation records

results/analysis.json, results/role_factory.patch and results/java_build.json.

`results/test_log.txt` contains the test log. `results/verification.json` records the test count, exit status and Python version. `CHECKSUMS.sha256` lists file hashes.
