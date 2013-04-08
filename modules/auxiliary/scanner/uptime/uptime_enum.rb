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

  def initialize
    super(
      'Name'        => 'uptimesoftware.com service enumerator',
      'Description' => 'Check to see what info uptime software exposes.',
      'Author'      => 'RogueBit',
      'License'     => MSF_LICENSE
    )
    register_options([
      Opt::RPORT(9998)], self.class)
  end

  def run_host(ip)
    begin
      print_status "#{rhost}:#{rport} - Sending sysinfo request."
      uptime_put("sysinfo")
      print_status "#{rhost}:#{rport} - Sending df-k request."
      uptime_put("df-k")
      print_status "#{rhost}:#{rport} - Sending lastuser request."
      uptime_put("lastuser")
      print_status "#{rhost}:#{rport} - Sending mpstat request."
      uptime_put("mpstat")
      print_status "#{rhost}:#{rport} - Sending netstat request."
      uptime_put("netstat")
      print_status "#{rhost}:#{rport} - Sending physdrv request."
      uptime_put("physdrv")
      print_status "#{rhost}:#{rport} - Sending psinfo request."
      uptime_put("psinfo")
      print_status "#{rhost}:#{rport} - Sending tcpinfo request."
      uptime_put("tcpinfo")
      print_status "#{rhost}:#{rport} - Sending whoin request."
      uptime_put("whoin")

    rescue ::Rex::ConnectionError
    rescue ::Exception => e
      print_error("#{e} #{e.backtrace}")
    end
    report_service(:host => rhost, :port => rport, :name => "uptime")
  end

  def uptime_put(marap)
    connect
    sock.put(marap)
                data = sock.recv(1024)
                print_status("Received: \r\n#{data}")
    disconnect
  end

end

