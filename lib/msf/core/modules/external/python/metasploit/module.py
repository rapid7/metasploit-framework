import json
import logging
import os
import sys


class LogFormatter(logging.Formatter):
    def __init__(self, prefix, *args, **kwargs):
        super(LogFormatter, self).__init__(*args, **kwargs)
        self.prefix = prefix

    def format(self, record):
        return self.prefix + record.msg


class LogHandler(logging.Handler):
    def emit(self, record):
        level = 'debug'
        if record.levelno >= logging.ERROR:
            level = 'error'
        elif record.levelno >= logging.WARNING:
            level = 'warning'
        elif record.levelno >= logging.INFO:
            level = 'info'
        log(self.format(record), level)
        return

    @classmethod
    def setup(cls, level=logging.DEBUG, name=None, msg_prefix=None):
        logger = logging.getLogger(name)
        handler = cls()

        if level is not None:
            logger.setLevel(level)
        if msg_prefix is not None:
            handler.setFormatter(LogFormatter(msg_prefix))
        logger.addHandler(handler)
        return handler


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
        rpc_send({'jsonrpc': '2.0', 'id': req['id'], 'result': metadata})
    elif req['method'] == 'run':
        args = req['params']
        module_callback(args)
        rpc_send({'jsonrpc': '2.0', 'id': req['id'], 'result': {
            'message': 'Module completed'
        }})


def report(kind, data):
    rpc_send({'jsonrpc': '2.0', 'method': 'report', 'params': {
        'type': kind, 'data': data
    }})


def rpc_send(req):
    print(json.dumps(req))
    sys.stdout.flush()
