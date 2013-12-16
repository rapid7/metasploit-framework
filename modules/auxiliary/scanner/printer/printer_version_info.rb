##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require "msf/core"
require "rex/proto/pjl"

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name' => "Printer Version Information Scanner",
      'Description' => %q{
        This module scans for printer version information using PJL.
      },
      'Author' => [
        "wvu", # This implementation
        "MC", # Independent implementation
        "YGN" # Independent implementation
      ],
      'References' => [
        ["URL", "https://en.wikipedia.org/wiki/Printer_Job_Language"]
      ],
      'License' => MSF_LICENSE
    ))

    register_options([
      Opt::RPORT(9100)
    ], self.class)
  end

  def run_host(ip)
    connect
    pjl = Rex::Proto::PJL::Client.new(sock)
    pjl.begin_job
    id = pjl.info_id
    pjl.end_job
    disconnect

    if id
      print_good("#{ip}:#{rport} - #{id}")
      report_service({
        :host => ip,
        :port => rport,
        :proto => "tcp",
        :name => "jetdirect",
        :info => id
      })
    end
  end

end
