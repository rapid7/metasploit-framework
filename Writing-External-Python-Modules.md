# Writing Python Modules for Metasploit

This is an example of how to write a Python module for Metasploit Framework that uses a Python metasploit library to communicate with framework via JSON-RPC over stdin/stdout.

## Python Library

The library currently supports a few function calls that can be used to report information to Metasploit Framework. The `metasploit` library can be loaded into your Python module by including the following line:

```python
from metasploit import module
```

The location of the [metasploit library](https://github.com/rapid7/metasploit-framework/tree/master/lib/msf/core/modules/external/python) is automatically added to the `PYTHONPATH` environment variable before the Python module is executed.

## Describe Yourself

Metasploit modules include information about authors of the modules, references to other sources with information about the vulnerabilities, descriptions of the modules, options, etc.

Python modules need to include this metadata information as well. The structure of the data is similar to modules written in Ruby. The following is an example template of metadata information:

```python
metadata = {
    'name': '<name>',
    'description': '''
        <description>
    ''',
    'authors': [
        '<author>',
        '<author>'
    ],
    'date': 'YYYY-MM-DD',
    'license': '<license>',
    'references': [
        {'type': 'url', 'ref': '<url>'},
        {'type': 'cve', 'ref': 'YYYY-#'},
        {'type': 'edb', 'ref': '#'},
        {'type': 'aka', 'ref': '<name>'}
    ],
    'type': '<module type>',
    'options': {
        '<name>': {'type': 'address', 'description': '<description>', 'required': <True/False>, 'default': None},
        '<name>': {'type': 'string', 'description': '<description>', 'required': <True/False>, 'default': None},
        '<name>': {'type': 'string', 'description': '<description>', 'required': <True/False>, 'default': None}
    }
}
```

### Module Type

As shown in the metadata template information, a `type` is also include for the module. The module type is used to select an ERB template, which generates a Ruby document for the module. The ERB templates can be found [here](https://github.com/rapid7/metasploit-framework/tree/master/lib/msf/core/modules/external/templates). The following templates are currently available:

```
remote_exploit_cmd_stager
capture_server
dos
single_scanner
multi_scanner
```

The `remote_exploit_cmd_stager` module type is used when writing an exploit for command execution or code injection vulnerabilities and provides the command to inject into the vulnerable code based on the [flavor](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-command-stagers) specified for the command stager.

The `capture_server` module type is used when a module is designed to simulate a service to capture credentials for connecting clients.

The `dos` module type is used when the module will send packets to a remote service that will crash the service or put it in an unusable state.

The `single_scanner` module type is used when creating a module to scan hosts without batching.

The `multi_scanner` module type is used for modules that are going to scan hosts in batches. The `batch_size` option is registered in the mutli_scanner ERB template with a default of 200.

### Options

The `options` dictionary in the metadata are the options that will be available in msfconsole when the module is loaded. The options can be required (necessary for the module to run) or not (provide additional functionality).

### Communication

To pass the metadata information, as well as the starting function of your Python module, to msfconsole, use the `module.run()` function. The `module.run()` function takes two arguments, the first is the metadata and the second is the callback function to use when executing the module from msfconsole. The code snippet will look like the following:

```python
def run(args):
    # Your code here
    pass


if __name__ == '__main__':
    module.run(metadata, run)
```

When msfconsole sends a `describe` request to the Python module, the metadata information is returned. When msfconsole sends a `run` request to the module, the callback function, `run` in this example, will be called with the arguments provided to msfconsole.

A [LogHandler](https://github.com/rapid7/metasploit-framework/pull/9739) can be setup and used to communicate status information back to framework during execution of the Python module. Here is code snippet that uses the LogHandler:

```python
import logging
from metasploit import module

module.LogHandler.setup(msg_prefix='logging test: ')
logging.info('info')
logging.error('error')
logging.warning('warning')
logging.debug('debug')
```

The `module.LogHandler.setup()` function is used the create a Handler and Formatter that will call `module.log()` with the appropriate log level.

## Full Example

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
import logging

# extra modules
dependencies_missing = False
try:
    import requests
except ImportError:
    dependencies_missing = True

from metasploit import module


metadata = {
    'name': 'Python Module Example',
    'description': '''
        Python communication with msfconsole.
    ''',
    'authors': [
        'Jacob Robles'
    ],
    'date': '2018-03-22',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://blog.rapid7.com/2017/12/28/regifting-python-in-metasploit/'},
        {'type': 'aka', 'ref': 'Coldstone'}
    ],
    'type': 'single_scanner',
    'options': {
        'targeturi': {'type': 'string', 'description': 'The base path', 'required': True, 'default': '/'},
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None}
    }
}


def run(args):
    module.LogHandler.setup(msg_prefix='{} - '.format(args['rhost']))
    if dependencies_missing:
        logging.error('Module dependency (requests) is missing, cannot continue')
        return

    # Your code here
    try:
        r = requests.get('https://{}/{}'.format(args['rhost'], args['targeturi']), verify=False)
    except requests.exceptions.RequestException as e:
        logging.error('{}'.format(e))
        return

    logging.info('{}...'.format(r.text[0:50]))


if __name__ == '__main__':
    module.run(metadata, run)
```
The example sends a get request to the given `rhost` and `targeturi`, then calls `logging.info()` on the result to have the output displayed in msfconsole.

## Coding with Style

All the Python code in Metasploit aims to be [PEP 8](https://www.python.org/dev/peps/pep-0008/) compliant. The biggest differences coming from Metasploit's Ruby style:
  * Two lines between functions (but not class methods)
  * Two lines between different types of code (like imports and the metadata, see above)
  * Four spaces for indenting

Some coding choices to think about when writing your module:
  * Prefer `"foo {}".format('bar')` over interpolation with `%`
  * Keep your callback methods short and readable. If it gets cluttered, break out sub-tasks into well-named functions
  * Variable names should be descriptive, readable, and short ([a guide](http://journal.stuffwithstuff.com/2016/06/16/long-names-are-long))
  * If you really need Python3 features in your module, use `#!/usr/bin/env python3` for the shebang
  * If you have a lot of legacy code in 2.7 or need a 2.7 library, use `#!/usr/bin/env python2.7` (macOS in particular does not ship with a `python2` executable by default)
  * If possible, have your module compatible with both and use `#!/usr/bin/env python`

## (Potentially) Common Questions

### Why doesn't the module appear when I search for it in msfconsole?

The module may have errors and fail to load inside of msfconsole. Check the framework log file, `~/.msf4/logs/framework.log`, for error messages. Also, if the module is not marked as executable, then it will not show up when you search for it in msfconsole.

### Why is the output from the Python module not showing up in msfconsole?

The external modules communicate with framework via JSON-RPC. If your Python module contains `print` statements, framework may not recognize those as JSON-RPC requests. Use the `LogHandler` or `module.log()` to send status information, which will be displayed in msfconsole.

## Additional Resources

[Rapid7 Blog: Regifting Python in Metasploit](https://blog.rapid7.com/2017/12/28/regifting-python-in-metasploit/)

[Rapid7 Blog: External Metasploit Modules: The Gift That Keeps On Slithering](https://blog.rapid7.com/2018/09/05/external-metasploit-modules-the-gift-that-keeps-on-slithering/)

[Metasploit Python library](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/modules/external/python/)

[ERB Templates](https://github.com/rapid7/metasploit-framework/tree/master/lib/msf/core/modules/external/templates)
