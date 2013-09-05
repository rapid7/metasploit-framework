##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::SMB
  include Msf::Auxiliary::Fuzzer

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'SMB Create Pipe Request Corruption',
      'Description'    => %q{
        This module sends a series of SMB create pipe requests with corrupted bytes.
      },
      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE
    ))
    register_options([
      OptInt.new('MAXDEPTH', [false, 'Specify a maximum byte depth to test']),
      OptString.new('SMBPIPE', [true, 'Specify the pipe name to corrupt', "\\BROWSER"])
    ], self.class)
  end

  def do_smb_login(pkt,opts={})
    @connected = false
    connect
    smb_login

    @connected = true
    sock.put(pkt)
    sock.get_once(-1, opts[:timeout])
  end

  def run

    # Connect in order to get the server-assigned user-id/tree-id
    connect
    smb_login
    pkt = make_smb_create
    disconnect

    last_str = nil
    last_inp = nil
    last_err = nil

    cnt = 0

    max = datastore['MAXDEPTH'].to_i
    max = nil if max == 0
    tot = ( max ? [max,pkt.length].min : pkt.length) * 256

    print_status("Fuzzing SMB create pipe with #{tot} requests")
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

  def make_smb_create

    filename = datastore['SMBPIPE']
    disposition = 1
    impersonation = 2

    pkt = Rex::Proto::SMB::Constants::SMB_CREATE_PKT.make_struct
    self.simple.client.smb_defaults(pkt['Payload']['SMB'])

    pkt['Payload']['SMB'].v['Command'] =  Rex::Proto::SMB::Constants::SMB_COM_NT_CREATE_ANDX
    pkt['Payload']['SMB'].v['Flags1'] = 0x18
    pkt['Payload']['SMB'].v['Flags2'] = 0x2001
    pkt['Payload']['SMB'].v['WordCount'] = 24

    pkt['Payload'].v['AndX'] = 255
    pkt['Payload'].v['FileNameLen'] = filename.length
    pkt['Payload'].v['CreateFlags'] = 0x16
    pkt['Payload'].v['AccessMask'] = 0x02000000 # Maximum Allowed
    pkt['Payload'].v['ShareAccess'] = 7
    pkt['Payload'].v['CreateOptions'] = 0
    pkt['Payload'].v['Impersonation'] = impersonation
    pkt['Payload'].v['Disposition'] = disposition
    pkt['Payload'].v['Payload'] = filename + "\x00"
    pkt.to_s
  end
end
