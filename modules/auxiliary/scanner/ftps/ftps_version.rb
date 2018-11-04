##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'FTPS Version Scanner',
      'Description' => 'Detect FTPS Version.',
      'References'  =>
        [
          ['URL', 'https://en.wikipedia.org/wiki/FTPS'],
        ],
      'Author'      => 'Ismail Tasdelen <ismailtasdelen[at]protonmail.com>',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(990),
      ])
  end

  def run_host(target_host)

    begin

    res = connect(true, false)

    if(banner)
      banner_sanitized = Rex::Text.to_hex_ascii(self.banner.to_s)
      print_good("FTPS Banner: '#{banner_sanitized}'")
      report_service(:host => rhost, :port => rport, :name => "ftps", :info => banner_sanitized)
    end

    disconnect

    rescue ::Interrupt
      raise $!
    rescue ::Rex::ConnectionError, ::IOError
    end

  end
end
