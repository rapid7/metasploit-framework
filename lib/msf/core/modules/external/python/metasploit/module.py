import sys, os, json


def log(message, level='info'):
    rpc_send({'jsonrpc': '2.0', 'method': 'message', 'params': {
        'level': level,
        'message': message
    }})


def report_host(ip, **opts):
    host = opts.copy()
    host.update({'host': ip})
    rpc_send({'jsonrpc': '2.0', 'method': 'report', 'params': {
        'type': 'host', 'data': host
    }})


def report_service(ip, **opts):
    service = opts.copy()
    service.update({'host': ip})
    rpc_send({'jsonrpc': '2.0', 'method': 'report', 'params': {
        'type': 'service', 'data': service
    }})


def report_vuln(ip, name, **opts):
    vuln = opts.copy()
    vuln.update({'host': ip, 'name': name})
    rpc_send({'jsonrpc': '2.0', 'method': 'report', 'params': {
        'type': 'vuln', 'data': vuln
    }})


def run(metadata, module_callback):
    req = json.loads(os.read(0, 10000))
    if req['method'] == 'describe':
        rpc_send({'jsonrpc': '2.0', 'id': req['id'], 'response': metadata})
    elif req['method'] == 'run':
        args = req['params']
        module_callback(args)
        rpc_send({'jsonrpc': '2.0', 'id': req['id'], 'response': {
            'message': 'Module completed'
        }})


def rpc_send(req):
    print(json.dumps(req))
    sys.stdout.flush()
