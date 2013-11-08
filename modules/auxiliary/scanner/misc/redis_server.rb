##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Tcp

  def initialize(info={})
    super(update_info(info,
      'Name'         => 'Redis-server Scanner',
      'Description'  => %q{
          This module scans for Redis server. By default Redis has no auth. If auth
        (password only) is used, it is then possible to execute a brute force attack on
        the server. This scanner will find open or password protected Redis servers and
        report back the server information
      },
      'Author'       => [ 'iallison <ian[at]team-allison.com>' ],
      'License'      => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(6379),
      ], self.class)

    deregister_options('RHOST')
  end

  def run_host(ip)
    print_status("Scanning IP: #{ip.to_s}")
    begin
      pkt = "PING" + "\n"
      connect()
      sock.puts(pkt)
      res = sock.recv(1024)

      if res =~ /PONG/
        info = "INFO"
        sock.puts(info)
        data = sock.recv(1024)
        print_status("Redis Server Information #{data}")
        data_sanitized = data.to_s
      elsif res =~ /ERR/
        auth = "AUTH foobared" + "\n"
        sock.puts(auth)
        data = sock.recv(1024)
        print_status("Response: #{data.chop}")
        if data =~ /\-ERR\sinvalid\spassword/
          print_status("Redis server is using AUTH")
        else
          print_good("Redis server is using the default password of foobared")
          report_note(
            :host => rhost,
            :port => rport,
            :type => 'password',
            :data => 'foobared'
          )
        end
      else
        print_error "#{ip} does not have a Redis server"
      end

      report_service(
        :host => rhost,
        :port => rport,
        :name => "redis server",
        :info => data_sanitized
      )

      disconnect

    rescue ::Exception => e
      print_error "Unable to connect: #{e.to_s}"
    end
  end
end
