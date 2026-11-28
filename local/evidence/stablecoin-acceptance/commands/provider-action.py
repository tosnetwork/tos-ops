"""One journaled provider token action (pause/resume) through the provider CLI's own
preview, digest confirmation and custody journal. Inputs and results are kept under
the acceptance state; the provider state is the running provider's, via its rail config."""
import json, subprocess, sys
from pathlib import Path
sys.path.insert(0, '/tos/worktrees/tos-ops/stablecoin-acceptance/testnet/scripts')
import transaction_archive as a
name, rail, actor, operation, binary = sys.argv[1:6]
assert operation in ('pause', 'resume')
directory = Path('/data/stablecoin-acceptance/provider-actions') / name
directory.mkdir(mode=0o700, parents=True, exist_ok=True)
inp = {'actor': actor, 'operation': operation, 'idempotency_key': 'stablecoin-acceptance-' + name}
path = directory / 'input.json'
if path.exists():
    assert json.loads(path.read_text()) == inp, 'journaled input differs'
else:
    a.document(path, inp)
command = ['/usr/bin/python3', '/tos/stablecoin-acceptance-tools/with-env.py', binary, 'token', '--rail-config', rail, '--input', str(path)]
preview = directory / 'preview.json'
if not preview.exists():
    run = subprocess.run(command, capture_output=True, text=True, timeout=180)
    if run.returncode not in (0, 4):
        raise SystemExit('provider preview refused: ' + run.stderr[-1000:])
    a.document(preview, json.loads(run.stdout))
digest = json.loads(preview.read_text())['preview']['digest']
a.document(directory / 'execution-intent.json', {'input': inp, 'confirmed_digest': digest})
run = subprocess.run(command + ['--yes', '--confirmed-digest', digest], capture_output=True, text=True, timeout=180)
if run.stdout:
    a.sync_write(directory / 'result.json', run.stdout.encode())
if run.returncode:
    raise SystemExit('provider action refused: ' + run.stderr[-1000:])
r = json.loads(run.stdout)
print(json.dumps({'operation': operation, 'state': r.get('state'), 'transaction': r.get('transaction'), 'call': r.get('call')}))
