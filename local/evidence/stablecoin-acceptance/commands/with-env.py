import json,os,sys
from pathlib import Path
# The local custody environment of the existing token-actor runs; never printed.
os.environ.update(json.loads(Path('/data/service-token-t10/env.json').read_text()))
os.execv(sys.argv[1],sys.argv[1:])
