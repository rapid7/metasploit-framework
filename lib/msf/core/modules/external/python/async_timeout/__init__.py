# Vendored from https://github.com/aio-libs/async-timeout
# Copyright: 2016-2017 Andrew Svetlov
# License: Apache 2.0

import asyncio


__version__ = '2.0.0'


class timeout:
    """timeout context manager.

    Useful in cases when you want to apply timeout logic around block
    of code or in cases when asyncio.wait_for is not suitable. For example:

    >>> async with timeout(0.001):
    ...     async with aiohttp.get('https://github.com') as r:
    ...         await r.text()


    timeout - value in seconds or None to disable timeout logic
    loop - asyncio compatible event loop
    """
    def __init__(self, timeout, *, loop=None):
        self._timeout = timeout
        if loop is None:
            loop = asyncio.get_event_loop()
        self._loop = loop
        self._task = None
        self._cancelled = False
        self._cancel_handler = None
        self._cancel_at = None

    def __enter__(self):
        return self._do_enter()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._do_exit(exc_type)

    @asyncio.coroutine
    def __aenter__(self):
        return self._do_enter()

    @asyncio.coroutine
    def __aexit__(self, exc_type, exc_val, exc_tb):
        self._do_exit(exc_type)

    @property
    def expired(self):
        return self._cancelled

    @property
    def remaining(self):
        if self._cancel_at is not None:
            return max(self._cancel_at - self._loop.time(), 0.0)
        else:
            return None

    def _do_enter(self):
        # Support Tornado 5- without timeout
        # Details: https://github.com/python/asyncio/issues/392
        if self._timeout is None:
            return self

        self._task = current_task(self._loop)
        if self._task is None:
            raise RuntimeError('Timeout context manager should be used '
                               'inside a task')

        if self._timeout <= 0:
            self._loop.call_soon(self._cancel_task)
            return self

        self._cancel_at = self._loop.time() + self._timeout
        self._cancel_handler = self._loop.call_at(
            self._cancel_at, self._cancel_task)
        return self

    def _do_exit(self, exc_type):
        if exc_type is asyncio.CancelledError and self._cancelled:
            self._cancel_handler = None
            self._task = None
            raise asyncio.TimeoutError
        if self._timeout is not None and self._cancel_handler is not None:
            self._cancel_handler.cancel()
            self._cancel_handler = None
        self._task = None

    def _cancel_task(self):
        self._task.cancel()
        self._cancelled = True


def current_task(loop):
    task = asyncio.Task.current_task(loop=loop)
    if task is None:
        if hasattr(loop, 'current_task'):
            task = loop.current_task()

    return task
