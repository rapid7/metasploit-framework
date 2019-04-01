# CVE-2018-8897
Demo exploitation of the POP SS vulnerability (CVE-2018-8897), leading to unsigned code execution with kernel privilages.
- KVA Shadowing should be disabled and [the relevant security update](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8897) should be uninstalled.
- This may not work with certain hypervisors (like VMWare), which discard the pending #DB after INT3. 

## Detailed explanation:

https://blog.can.ac/2018/05/11/arbitrary-code-execution-at-ring-0-using-cve-2018-8897/

## Result:
![](https://blog.can.ac/wp-content/uploads/2018/05/K1DL2.png)
![](https://blog.can.ac/wp-content/uploads/2018/05/aF6dL.png)
