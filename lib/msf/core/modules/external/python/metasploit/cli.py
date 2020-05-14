

import argparse
import json
import re
import sys


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def log(message, level='info'):
    # logging goes to stderr
    sigil = '*'
    if level == 'warning' or level == 'error':
        sigil = '!'
    elif level == 'good':
        sigil = '+'
    eprint('[{}] {}'.format(sigil, message))


def report(kind, data):
    # actual results go to stdout
    print("[+] Found {}: {}".format(kind, json.dumps(data, separators=(',', ':'))))


def ret(result):
    print(result)


def parse(meta):
    parser = argparse.ArgumentParser(description=meta['description'])
    actions = ['run'] + meta['capabilities']
    parser.add_argument(
            'action',
            nargs='?',
            metavar="ACTION",
            help="The action to take ({})".format(actions),
            default='run',
            choices=actions)

    required_group = parser.add_argument_group('required arguments')
    for opt, props in list(meta['options'].items()):
        group = parser
        desc = props['description']
        required = props['required'] and (props.get('default', None) is None)
        if props.get('default', None) is not None:
            desc = "{}, (default: {})".format(props['description'], props['default'])

        if required:
            group = required_group
        group.add_argument(
                '--' + opt.replace('_', '-'),
                help=desc,
                default=props.get('default', None),
                type=choose_type(props['type']),
                required=required,
                dest=opt)

    opts = parser.parse_args()
    args = vars(opts)
    action = args['action']
    del args['action']
    return {'id': '0', 'params': args, 'method': action}


def choose_type(t):
    if t == 'int' or t == 'port':
        return int
    elif t == 'float':
        return float
    elif re.search('range$', t):
        return comma_list
    else: # XXX TODO add validation for addresses and other MSF option types
        return str


def comma_list(v):
    return v.split(',')
