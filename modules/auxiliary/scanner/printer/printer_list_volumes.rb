##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require "rex/proto/pjl"

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      "Name" => "Printer Volume Listing Scanner",
      "Description" => %q{
        This module lists the volumes on a set of printers using the
        Printer Job Language (PJL) protocol.
      },
      "Author" => [
        "wvu", # Rex::Proto::PJL and modules
        "sinn3r", # RSpec tests
        "MC", # Independent mixin and modules
        "Myo Soe", # Independent modules
        "Matteo Cantoni <goony[at]nothink.org>" # Independent modules
      ],
      "References" => [
        ["URL", "https://en.wikipedia.org/wiki/Printer_Job_Language"]
      ],
      "License" => MSF_LICENSE
    ))

    register_options([
      Opt::RPORT(Rex::Proto::PJL::DEFAULT_PORT),
    ])
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
      print_good("#{ip}:#{rport} - #{listing}")
      report_note(
        :host => ip,
        :port => rport,
        :proto => "tcp",
        :type => "printer.vol.listing",
        :data => listing
      )
    end
  end
end
