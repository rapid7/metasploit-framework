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
      "Name" => "Printer Ready Message Scanner",
      "Description" => %q{
        This module scans for and optionally changes the printer ready message on
        a set of printers using the Printer Job Language (PJL) protocol.
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
      "License" => MSF_LICENSE,
      "Actions" => [
        ["Scan", "Description" => "Scan for ready messages"],
        ["Change", "Description" => "Change ready message"],
        ["Reset", "Description" => "Reset ready message"]
      ],
      "DefaultAction" => "Scan"
    ))

    register_options([
      Opt::RPORT(Rex::Proto::PJL::DEFAULT_PORT),
      OptString.new("MESSAGE", [false, "Ready message", "PC LOAD LETTER"])
    ])
  end

  def run_host(ip)
    connect
    pjl = Rex::Proto::PJL::Client.new(sock)
    pjl.begin_job

    case action.name
    when "Change"
      pjl.set_rdymsg(datastore["MESSAGE"])
    when "Reset"
      pjl.set_rdymsg("")
    end

    rdymsg = pjl.get_rdymsg

    pjl.end_job
    disconnect

    if rdymsg
      print_good("#{ip}:#{rport} - #{rdymsg}")
      report_note(
        :host => ip,
        :port => rport,
        :proto => "tcp",
        :type => "printer.rdymsg",
        :data => { :rdymsg => rdymsg }
      )
    end
  end
end
