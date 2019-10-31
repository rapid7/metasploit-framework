import time

from metasploit import module


def make_scanner(login_callback):
    return lambda args: run_scanner(args, login_callback)


def run_scanner(args, login_callback):
    userpass = args['userpass'] or []
    rhost = args['rhost']
    rport = int(args['rport'])
    sleep_interval = float(args['sleep_interval'] or 0)

    if isinstance(userpass, str) or isinstance(userpass, str):
        userpass = [ attempt.split(' ', 1) for attempt in userpass.splitlines() ]

    curr = 0
    total = len(userpass)
    pad_to = len(str(total))

    for [username, password] in userpass:
        try:
            # Call per-combo login function
            curr += 1
            if login_callback(rhost, rport, username, password):
                module.log('{}:{} - [{:>{pad_to}}/{}] - {}:{} - Success'
                        .format(rhost, rport, curr, total, username, password, pad_to=pad_to), level='good')
                module.report_correct_password(username, password)
            else:
                module.log('{}:{} - [{:>{pad_to}}/{}] - {}:{} - Failure'
                        .format(rhost, rport, curr, total, username, password, pad_to=pad_to), level='info')
                module.report_wrong_password(username, password)

            time.sleep(sleep_interval)
        except Exception as e:
            module.log('{}:{} - [{:>{pad_to}}/{}] - {}:{} - Error: {}'
                    .format(rhost, rport, curr, total, username, password, e, pad_to=pad_to), level='error')
