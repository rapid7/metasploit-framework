CVE-2019-0708 BlueKeep RDP Remote Windows Kernel Use After Free

The RDP termdd.sys driver improperly handles binds to internal-only channel MS_T120, allowing a malformed Disconnect Provider Indication message to cause use-after-free.  With a controllable data/size remote nonpaged pool spray, an indirect call gadget of the freed channel is used to achieve arbitrary code execution.

## Vulnerable Application

This exploit should work against a vulnerable RDP service from one of these Windows systems:

* Windows 2000 x86 (All Service Packs))
* Windows XP x86 (All Service Packs))
* Windows 2003 x86 (All Service Packs))
* Windows 7 x86 (All Service Packs))
* Windows 7 x64 (All Service Packs)
* Windows 2008 R2 x64 (All Service Packs)

This exploit module currently targets these Windows systems running on several virtualized and physical targets.

* Windows 7 x64 (All Service Packs)
* Windows 2008 R2 x64 (All Service Packs)

## Verification Steps

- [ ] Start `msfconsole`
- [ ] `use exploit/windows/rdp/cve_2019_0708_bluekeep_rce`
- [ ] `set RHOSTS` to Windows 7/2008 x64
- [ ] `set TARGET` based on target host characteristics
- [ ] `set PAYLOAD`
- [ ] `exploit`
- [ ] **Verify** that you get a shell
- [ ] **Verify** that you do not crash

## Options
