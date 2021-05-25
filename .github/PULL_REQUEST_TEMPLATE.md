Tell us what this change does. If you're fixing a bug, please mention
the github issue number.

Please ensure you are submitting **from a unique branch** in your [repository](https://github.com/rapid7/metasploit-framework/pull/11086#issuecomment-445506416) to master in Rapid7's.

## Verification

List the steps needed to make sure this thing works

- [ ] Start `msfconsole`
- [ ] `use exploit/windows/smb/ms08_067_netapi`
- [ ] ...
- [ ] **Verify** the thing does what it should
- [ ] **Verify** the thing does not do what it should not
- [ ] **Document** the thing and how it works ([Example](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/gather/aws_keys.md))

If you are opening a PR for a new module that exploits a **specific** piece of hardware or requires a **complex or hard-to-find** testing environment, we recommend that you send us a demo of your module executing correctly. Seeing your module in action will help us review your PR faster!

Specific Hardware Examples:
* Switches
* Routers
* IP Cameras
* IoT devices

Complex Software Examples:
* Expensive proprietary software
* Software with an extensive installation process
* Software that requires exploit testing across multiple significantly different versions
* Software without an English language UI

We will also accept demonstrations of successful module execution even if your module doesn't meet the above conditions. It's not a necessity, but it may help us land your module faster!

Demonstration of successful module execution can take the form of a packet capture (pcap) or a screen recording. You can send pcaps and recordings to [msfdev@metasploit.com](mailto:msfdev@metasploit.com). Please include a CVE number in the subject header (if applicable), and a link to your PR in the email body.
