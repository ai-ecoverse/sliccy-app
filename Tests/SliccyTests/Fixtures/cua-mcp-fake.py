# Synthetic stdio fixture: no Cua, GUI, network, permissions or desktop access.
import json
import sys
import time

for line in sys.stdin:
    request = json.loads(line)
    if 'id' not in request:
        continue
    method = request['method']
    if method == 'initialize':
        result = {'protocolVersion': '2025-06-18', 'capabilities': {'tools': {}}, 'serverInfo': {'name': 'fake', 'version': '1'}}
    elif method == 'tools/list':
        result = {'tools': [{'name': 'fake_echo', 'description': 'Synthetic echo', 'inputSchema': {'type': 'object'}}]}
    elif method == 'tools/call':
        args = request.get('params', {}).get('arguments', {})
        if args.get('exit'):
            sys.exit(0)
        if args.get('sleep'):
            time.sleep(args['sleep'])
        result = {'content': [{'type': 'text', 'text': json.dumps(args)}]}
    else:
        result = {}
    print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': result}), flush=True)
