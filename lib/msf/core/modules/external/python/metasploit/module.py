import json
import os
import sys


def log(message, level='info'):
    rpc_send({'jsonrpc': '2.0', 'method': 'message', 'params': {
        'level': level,
        'message': message
    }})


def report_host(ip, **opts):
    host = opts.copy()
    host.update({'host': ip})
    report('host', host)


def report_service(ip, **opts):
    service = opts.copy()
    service.update({'host': ip})
    report('service', service)


def report_vuln(ip, name, **opts):
    vuln = opts.copy()
    vuln.update({'host': ip, 'name': name})
    report('vuln', vuln)


def run(metadata, module_callback):
    req = json.loads(os.read(0, 10000).decode("utf-8"))
    if req['method'] == 'describe':
        rpc_send({'jsonrpc': '2.0', 'id': req['id'], 'response': metadata})
    elif req['method'] == 'run':
        args = req['params']
        module_callback(args)
        rpc_send({'jsonrpc': '2.0', 'id': req['id'], 'response': {
            'message': 'Module completed'
        }})


def report(kind, data):
    rpc_send({'jsonrpc': '2.0', 'method': 'report', 'params': {
        'type': kind, 'data': data
    }})


def rpc_send(req):
    print(json.dumps(req))
    sys.stdout.flush()
