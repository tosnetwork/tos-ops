"""Archive the provider's journaled pause and resume actor transactions on nodes 4-6."""
import importlib.util, json
from pathlib import Path
s = importlib.util.spec_from_file_location('t', '/tos/worktrees/tos-ops/stablecoin-acceptance/local/scripts/local-pq-usdt.py')
t = importlib.util.module_from_spec(s); s.loader.exec_module(t)
a = t.archive
chain = t.u.Chain(Path('/data'))
actor = '0:dab3c57e833459f6b2481148009a8c0817540da8cfc1e64248be612f1fe06df3'
records = {
    'provider-auto-pause-usdt': '3f22d7eb898933beef115f9898eca3c405196ec6a15b00709f0a13a1bd922233',
    'provider-resume-usdt': '8f68e3fed8563b69defd9e6b2d197405f83f4e7880e3efbd18768e0ab5fbf260',
}
journal = a.StepJournal(Path('/data/stablecoin-acceptance/archive/provider'))
for label, record in records.items():
    d = json.loads((Path('/data/service-token-usdt-t18/published-provider/token-actions') / (record + '.json')).read_text())
    t.require(d['state'] == 'finalized' and d['input']['actor'] == actor, 'provider record is not a finalized action of this actor')
    root = {'account': actor, 'lt': int(d['call']['lt']), 'hash': d['call']['hash']}
    identity = a.digest(json.dumps(root, sort_keys=True).encode())
    manifest = journal.run(label, identity, lambda: None,
                           lambda directory: a.TransactionArchive(directory, chain.urls[3:6], t.GENESIS).capture_wait([root]))
    journal.retain_verifier(label + '-provider-record', {'operation': d['input']['operation'], 'state': d['state'], 'call': d['call'], 'transaction': d['transaction']})
    print(label, len(manifest['files']), 'files')
