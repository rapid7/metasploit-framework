
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

If you are opening a PR for a new Module that exploits a **specific** piece of hardware, or requires a **very** complex testing environment, we will need a demonstration of your module executing correctly in order to land your Module in a reasonable time. 

We will also accept demonstrations of successful Module execution if it doesn't match any of the above conditions and you think it will still help land your Module, but it is not a neccessity. 

Demonstration of successful Module execution can take the form of a Packet Capture, a Screen Recording, or a Video Conference with a member of the Metasploit team via your conferencing tool of choice. PCAPs, Screen Recordings, or times you are available for a Video Conference should be sent to [msfdev@metaspolit.com](mailto:msfdev@metaspolit.com).

