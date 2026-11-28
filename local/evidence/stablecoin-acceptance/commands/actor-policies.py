"""Both actors' get_service_data at one finalized checkpoint on nodes 4-6 (read-only)."""
import importlib.util, json, sys
from pathlib import Path
s = importlib.util.spec_from_file_location('t', '/tos/worktrees/tos-ops/stablecoin-acceptance/local/scripts/local-pq-usdt.py')
t = importlib.util.module_from_spec(s); s.loader.exec_module(t)
label = sys.argv[1]
out = Path('/data/stablecoin-acceptance/evidence'); refs = Path('/data/stablecoin-acceptance/references') / label
view = t.View(t.u.Chain(Path('/data')), refs)
actors = {'usdt': '0:dab3c57e833459f6b2481148009a8c0817540da8cfc1e64248be612f1fe06df3',
          'usdc': '0:3d56b9e8618d0e257925b7185880a45887b217b13d90baa1ed9bca8ac4bca8f2'}
values = {}
for asset, address in actors.items():
    rows = view.read('runGetMethod', address=address, method='get_service_data', stack=[])
    t.require(all(r['exit_code'] == 0 and r['stack'] == rows[0]['stack'] for r in rows), 'policy references differ')
    stack = rows[0]['stack']
    values[asset] = {'address': address, 'active': int(stack[1][1]), 'policy_version': int(stack[2][1]), 'stack': stack}
t.archive.document(out / (label + '.json'), {'checkpoint': view.point, 'endpoints': view.urls, 'actors': values})
print(json.dumps({k: {'active': v['active'], 'policy_version': v['policy_version']} for k, v in values.items()}))
