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
      'Name' => "Printer Ready Message Scanner",
      'Description' => %q{
        This module scans for and can change printer ready messages using PJL.
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
      Opt::RPORT(9100),
      OptBool.new("CHANGE", [false, "Change ready message", false]),
      OptString.new("MESSAGE", [false, "Ready message", "PC LOAD LETTER"])
    ], self.class)
  end

  def run_host(ip)
    connect
    pjl = Rex::Proto::PJL::Client.new(sock)
    if datastore["CHANGE"]
      message = datastore["MESSAGE"]
      pjl.set_rdymsg(message)
    end
    rdymsg = pjl.get_rdymsg
    disconnect

    if rdymsg
      print_good("#{ip} #{rdymsg}")
      report_note({
        :host => ip,
        :port => rport,
        :proto => "tcp",
        :type => "printer.rdymsg",
        :data => rdymsg
      })
    end
  end

end
