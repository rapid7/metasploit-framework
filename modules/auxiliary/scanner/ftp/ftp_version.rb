##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'FTP Version Scanner',
            'Description' => 'Detect FTP Version.',
            'Author'      => 'hdm',
            'License'     => MSF_LICENSE
        )
    )

    register_options(
      [
        Opt::RPORT(21),
      ], self.class)
  end

  def run_host(target_host)

    begin

    res = connect(true, false)

    if(banner)
      banner_sanitized = Rex::Text.to_hex_ascii(self.banner.to_s)
      print_status("#{rhost}:#{rport} FTP Banner: '#{banner_sanitized}'")
      report_service(:host => rhost, :port => rport, :name => "ftp", :info => banner_sanitized)
    end

    disconnect

    rescue ::Interrupt
      raise $!
    rescue ::Rex::ConnectionError, ::IOError
    end

  end
end
