For an introduction to the reasons and goals for external modules, [see our 2017 HaXmas post on the subject](https://blog.rapid7.com/2017/12/28/regifting-python-in-metasploit).

Request Flow
============

Each time Metasploit wants an external module to do something (ex. describe itself or run with a certain configuration), it runs the module in a new process and talks to it over stdin/stdout.

To get the metadata from a module (which includes options), the call sequence looks a bit like:
```
+------------+
| Metasploit |
|            |  Describe yourself  +-------------------+
|            +-------------------> |  some_module.py   |
|            |                     |                   |
|            |                     |                   |
|            |   Some metadata     |                   |
|            | <-------------------+                   |
|            |                     |                   |
|            |                     +-------------------+
|            |
|            |
+------------+
```

A module run might look like:
```
+------------+
| Metasploit |  Do a thing with
|            |   these options     +-------------------+
|            +-------------------> |  some_module.py   |
|            |                     |                   |
|            |                     |                   |
|            |   A bit of status   |                   |
|            | <-------------------+                   |
|            |                     |                   |
|            |  Moar status        |                   |
|            | <-------------------+                   |
|            |                     |                   |
|            |  I found a thing    |                   |
|            | <-------------------+                   |
|            |                     |                   |
|            |                     +-------------------+
|            |
+------------+
```

When a module meant for a single host is run against a range of hosts, Metasploit will start a new process for each host. If the `THREADS` datastore option is set and it is an auxiliary module, that many processes will be run at the same time.


JSON-RPC API
============

External modules communicate with Metasploit over stdin/stdout. The methods a module must implement are `describe` and `run`; additional methods can be advertised in the `capabilities` array, for now assumed to use a subset of the options used for `run`. Metasploit implements `message` and will implement `report` in the near future. The specs for each method are written below using [JSON-schema](https://spacetelescope.github.io/understanding-json-schema). Work still needs to be done enumerating valid types and codes for the messages.

Describe
--------
**Request**
```javascript
{
  "$schema": "http://json-schema.org/schema#",
  "type": "object",
  "required": ["params", "method", "jsonrpc", "id"],
  "properties": {
    "jsonrpc": {"enum": ["2.0"]},
    "id": {"type": "string"},
    "method": {"enum": ["describe"]},
    "params": {"type": "object"}
  }
}
```

**Response**
```javascript
{
  "$schema": "http://json-schema.org/schema#",
  "type": "object",
  "required": ["jsonrpc", "result", "id"],
  "properties": {
    "jsonrpc": {"enum": ["2.0"]},
    "id": {"type": "string"},
    "result": {
      "type": "object",
      "required": ["name", "description", "authors", "type", "options", "capabilities"],
      "properties": {
        "name": {"type": "string"},
        "description": {"type": "string"},
        "authors": {"type": "array", "items": {"type": "string"}},
        "date": {"type": "string"},
        "references": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["type", "ref"],
            "properties": {
              "type": {"type": "string"},
              "ref": {"type": "string"}
            }
          }
        },
        "type": {"enum": ["remote_exploit.cmd_stager.wget"]},
        "privileged": {"type": "boolean"},
        "targets": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["platform", "arch"],
            "properties": {
              "platform": {"type": "string"},
              "arch": {"type": "string"}
            }
          }
        },
        "options": {
          "type": "object",
          "additionalProperties": false,
          "patternProperties": {
            "^[^=]*$": {
              "type": "object",
              "required": ["type", "description", "required", "default"],
              "properties": {
                "required": {"type": "boolean"},
                "default": {"type": ["null", "string", "number", "boolean", "object", "array"]},
                "description": {"type": "string"},
                "type": {"type": "string"}
              }
            }
          }
        },
        "capabilities": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      }
    }
  }
}
```

Run
---
**Request**
```javascript
{
  "$schema": "http://json-schema.org/schema#",
  "type": "object",
  "required": ["params", "method", "jsonrpc", "id"],
  "properties": {
    "jsonrpc": {"enum": ["2.0"]},
    "id": {"type": "string"},
    "method": {"enum": ["run"]},
    "params": {
      "type": "object"
      "additionalProperties": false,
      "patternProperties": {
        "^[^=]*$": {
          "type": "object",
          "required": ["type", "description", "required", "default"],
          "properties": {
            "required": {"type": "boolean"},
            "default": {"type": ["null", "string", "number", "boolean", "object", "array"]},
            "description": {"type": "string"},
            "type": {"type": "string"}
          }
        }
      }
    }
  }
}
```

**Response**
```javascript
{
  "$schema": "http://json-schema.org/schema#",
  "type": "object",
  "required": ["jsonrpc", "id"],
  "properties": {
    "jsonrpc": {"enum": ["2.0"]},
    "id": {"type": "string"},
    "result": {
      "type": "object",
      "required": ["message"]
      "properties": {
        "message": {"type": "string"},
        "return": {"type": "string"}
      }
    },
    "error": {
      "type": "object",
      "required": ["message", "code"],
      "properties": {
        "message": {"type": "string"},
        "code": {"type": "number"},
        "data": {"type": "object"}
      }
    }
  }
}
```

Message
-------
Notification - no response
```javascript
{
  "$schema": "http://json-schema.org/schema#",
  "type": "object",
  "required": ["params", "method", "jsonrpc"],
  "properties": {
    "jsonrpc": {"enum": ["2.0"]},
    "method": {"enum": ["message"]},
    "params": {
      "type": "object",
      "required": ["level", "message"],
      "properties": {
        "level": {"enum": ["error", "good", "warning", "info", "debug"]},
        "message": {"type": "string"}
      }
    }
  }
}
```
