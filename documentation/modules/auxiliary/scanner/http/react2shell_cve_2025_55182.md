## Vulnerable Application

A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

## Testing

1. Open `data\auxiliary\http\react2shell_cve_2025_55182` directory
2. Build
```
docker build -t react2shell .
```
3. Run
```
docker run -p 3000:3000 react2shell
```
4. Open http://127.0.0.1:3000/ and make sure the app is available

## Scenario

```
msf6 > use multi/http/react2shell_cve_2025_55182_scanner
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(multi/http/react2shell_cve_2025_55182_scanner) > set RPORT 3000
RPORT => 3000
msf6 exploit(scanner/http/react2shell_cve_2025_55182_scanner) > set RHOSTS 127.0.0.1
RHOSTS => 172.17.0.1
msf6 auxiliary(scanner/http/react2shell_cve_2025_55182_scanner) > run

[+] The target http://127.0.0.1:3000 appears to be vulnerable
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```