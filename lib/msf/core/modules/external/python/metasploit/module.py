import json
import logging
import os
import sys

from metasploit import cli

__CLI_MODE__ = False


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
    if not __CLI_MODE__:
        rpc_send({'jsonrpc': '2.0', 'method': 'message', 'params': {
            'level': level,
            'message': message
        }})
    else:
        cli.log(message, level)


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


def report_correct_password(username, password, **opts):
    info = opts.copy()
    info.update({'username': username, 'password': password})
    report('correct_password', info)


def report_wrong_password(username, password, **opts):
    info = opts.copy()
    info.update({'username': username, 'password': password})
    report('wrong_password', info)


def run(metadata, module_callback, soft_check=None):
    global __CLI_MODE__

    caps = []
    if soft_check:
        caps.append('soft_check')

    meta = metadata.copy()
    meta.update({'capabilities': caps})

    if len(sys.argv) > 1:
        __CLI_MODE__ = True

    req = None
    if __CLI_MODE__:
        req = cli.parse(meta)
    else:
        req = json.loads(os.read(0, 10000).decode("utf-8"))

    callback = None
    if req['method'] == 'describe':
        rpc_send({'jsonrpc': '2.0', 'id': req['id'], 'result': meta})
    elif req['method'] == 'soft_check':
        if soft_check:
            callback = soft_check
        else:
            rpc_send({'jsonrpc': '2.0', 'id': req['id'], 'error': {'code': -32601, 'message': 'Soft checks are not supported'}})
    elif req['method'] == 'run':
        callback = module_callback

    if callback:
        args = req['params']
        ret = callback(args)
        if ret and __CLI_MODE__:
            cli.ret(ret)

        rpc_send({'jsonrpc': '2.0', 'id': req['id'], 'result': {
            'message': 'Module completed',
            'return': ret
        }})


def report(kind, data):
    if not __CLI_MODE__:
        rpc_send({'jsonrpc': '2.0', 'method': 'report', 'params': {
            'type': kind, 'data': data
        }})
    else:
        cli.report(kind, data)


def rpc_send(req):
    # Silently ignore when run manually, the calling code should know how to
    # handle if it is important
    if not __CLI_MODE__:
        print(json.dumps(req))
        sys.stdout.flush()
