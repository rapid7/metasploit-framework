import sys, os, json

def log(message, level='info'):
    print(json.dumps({'jsonrpc': '2.0', 'method': 'message', 'params': {
        'level': level,
        'message': message
    }}))
    sys.stdout.flush()

def run(metadata, exploit):
    req = json.loads(os.read(0, 10000))
    if req['method'] == 'describe':
        print(json.dumps({'jsonrpc': '2.0', 'id': req['id'], 'response': metadata}))
    elif req['method'] == 'run':
        args = req['params']
        exploit(args)
        print(json.dumps({'jsonrpc': '2.0', 'id': req['id'], 'response': {
            'message': 'Exploit completed'
        }}))
        sys.stdout.flush()
