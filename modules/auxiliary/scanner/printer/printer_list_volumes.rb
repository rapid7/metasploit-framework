##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require "msf/core"
require "rex/proto/pjl"

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      "Name" => "Printer Volume Listing Scanner",
      "Description" => %q{
        This module lists the volumes on a printer using PJL.
      },
      "Author" => [
        "wvu", # This implementation
        "sinn3r", # RSpec tests
        "MC", # Independent implementation
        "YGN" # Independent implementation
      ],
      "References" => [
        ["URL", "https://en.wikipedia.org/wiki/Printer_Job_Language"]
      ],
      "License" => MSF_LICENSE
    ))

    register_options([
      Opt::RPORT(Rex::Proto::PJL::DEFAULT_PORT),
    ], self.class)
  end

  def run_host(ip)
    connect
    pjl = Rex::Proto::PJL::Client.new(sock)
    pjl.begin_job

    3.times { |volume| pjl.fsinit("#{volume}:") }
    listing = pjl.info_filesys

    pjl.end_job
    disconnect

    if listing
      print_good("#{ip}:#{rport}\n#{listing}")
      report_note({
        :host => ip,
        :port => rport,
        :proto => "tcp",
        :type => "printer.vol.listing",
        :data => listing
      })
    end
  end

end
