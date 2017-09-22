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
      "Name" => "Printer Environment Variables Scanner",
      "Description" => %q{
        This module scans for printer environment variables using the
        Printer Job Language (PJL) protocol.
      },
      "Author" => [
        "wvu", # Rex::Proto::PJL and modules
        "sinn3r", # RSpec tests
        "MC", # Independent mixin and modules
        "Myo Soe", # Independent modules
        "Matteo Cantoni" # Independent modules
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

    env_vars = pjl.info_variables

    pjl.end_job
    disconnect

    if env_vars
      print_good("#{ip}:#{rport} - #{env_vars}")
      report_note(
        :host => ip,
        :port => rport,
        :proto => "tcp",
        :type => "printer.env.vars",
        :data => env_vars
      )
    end
  end
end
