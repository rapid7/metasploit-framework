import asyncio
import functools
import re

from async_timeout import timeout
from metasploit import module


def make_scanner(payload='', pattern='', onmatch=None, connect_timeout=3, read_timeout=10):
    return lambda args: start_scanner(payload, pattern, args, onmatch, connect_timeout=connect_timeout, read_timeout=read_timeout)


def start_scanner(payload, pattern, args, onmatch, **timeouts):
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run_scanner(payload, pattern, args, onmatch, **timeouts))


async def run_scanner(payload, pattern, args, onmatch, **timeouts):
    probes = [probe_host(host, int(args['rport']), payload, **timeouts) for host in args['rhosts']]
    async for (target, res) in Scan(probes):
        if isinstance(res, Exception):
            module.log('{}:{} - Error connecting: {}'.format(*target, res), level='error')
        elif res and re.search(pattern, res):
            module.log('{}:{} - Matches'.format(*target), level='good')
            module.log('{}:{} - Matches with: {}'.format(*target, res), level='debug')
            onmatch(target, res)
        else:
            module.log('{}:{} - Does not match'.format(*target), level='info')
            module.log('{}:{} - Does not match with: {}'.format(*target, res), level='debug')


class Scan:
    def __init__(self, runs):
        self.queue = asyncio.queues.Queue()
        self.total = len(runs)
        self.done = 0

        for r in runs:
            f = asyncio.ensure_future(r)
            args = r.cr_frame.f_locals
            target = (args['host'], args['port'])
            f.add_done_callback(functools.partial(self.__queue_result, target))

    def __queue_result(self, target, f):
        res = None

        try:
            res = f.result()
        except Exception as e:
            res = e

        self.queue.put_nowait((target, res))

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.done == self.total:
            raise StopAsyncIteration

        res = await self.queue.get()
        self.done += 1
        return res


async def probe_host(host, port, payload, connect_timeout, read_timeout):
    buf = bytearray()

    try:
        async with timeout(connect_timeout):
            r, w = await asyncio.open_connection(host, port)
            remote = w.get_extra_info('peername')
            if remote[0] == host:
                module.log('{}:{} - Connected'.format(host, port), level='debug')
            else:
                module.log('{}({}):{} - Connected'.format(host, *remote), level='debug')
            w.write(payload)
            await w.drain()

        async with timeout(read_timeout):
            while len(buf) < 4096:
                data = await r.read(4096)
                if data:
                    module.log('{}:{} - Received {} bytes'.format(host, port, len(data)), level='debug')
                    buf.extend(data)
                else:
                    break
    except asyncio.TimeoutError:
        if buf:
            pass
        else:
            raise
    finally:
        try:
            w.close()
        except Exception:
            # Either we got something and the socket got in a bad state, or the
            # original error will point to the root cause
            pass

    return buf
