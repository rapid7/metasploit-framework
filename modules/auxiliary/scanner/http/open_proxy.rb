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
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'HTTP Open Proxy Detection',
      'Description' => %q{
          Checks if an HTTP proxy is open. False positive are avoided
        verifing the HTTP return code and matching a pattern.
      },
      'References'  =>
        [
          ['URL', 'http://en.wikipedia.org/wiki/Open_proxy'],
          ['URL', 'http://nmap.org/svn/scripts/http-open-proxy.nse'],
        ],
      'Author'      => 'Matteo Cantoni <goony[at]nothink.org>',
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(8080),
        OptBool.new('DEBUG', [ false, 'Enable requests debugging output', false ]),
        OptBool.new('MULTIPORTS', [ false, 'Multiple ports will be used : 80, 1080, 3128, 8080, 8123', false ]),
        OptBool.new('RANDOMIZE_PORTS', [ false, 'Randomize the order the ports are probed', false ]),
        OptBool.new('VERIFY_CONNECT', [ false, 'Enable test for CONNECT method', false ]),
        OptBool.new('VERIFY_HEAD', [ false, 'Enable test for HEAD method', false ]),
        OptBool.new('LOOKUP_PUBLIC_ADDRESS', [ false, 'Enable test for retrieve public IP address via RIPE.net', false ]),
        OptString.new('SITE', [ true, 'The web site to test via alleged web proxy (default is www.google.com)', '209.85.148.147' ]),
        OptString.new('ValidCode', [ false, "Valid HTTP code for a successfully request", '200,302' ]),
        OptString.new('ValidPattern', [ false, "Valid HTTP server header for a successfully request", 'server: gws' ]),
        OptString.new('UserAgent', [ true, 'The HTTP User-Agent sent in the request', 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)' ]),
      ], self.class)

    register_advanced_options(
      [
        OptString.new('RIPE_ADDRESS', [ true, 'www.ripe.net IP address', '193.0.6.139' ]),
      ], self.class)

    register_wmap_options({
        'OrderID' => 1,
        'Require' => {},
      })
  end

  def run_host(target_host)

    target_ports = []

    if datastore['MULTIPORTS']
      target_ports = [ 80, 1080, 3128, 8080, 8123 ]
    else
      target_ports.push(datastore['RPORT'].to_i)
    end

    if datastore['RANDOMIZE_PORTS']
      target_ports = target_ports.sort_by { rand }
    end

    site       = datastore['SITE']
    user_agent = datastore['UserAgent']

    target_ports.each do |target_port|
      datastore['RPORT'] = target_port
      if target_host == site
        print_error("Target is the same as proxy site.")
      else
        check_host(target_host,target_port,site,user_agent)
      end
    end

  end

  def check_pattern(res,pattern)

    if (res =~ /#{pattern}/i)
      return 1
    else
      return 0
    end

  end

  def write_request(method,site,user_agent)

    request = method + " http://" + site + "/ HTTP/1.1" + "\r\n" +
      "Host: " + site + "\r\n" +
      "Connection: close" + "\r\n" +
      "User-Agent: user_agent" + "\r\n" +
      "Accept-Encoding: *" + "\r\n" +
      "Accept-Charset: ISO-8859-1,UTF-8;q=0.7,*;q=0.7" + "\r\n" +
      "Cache-Control: no" + "\r\n" +
      "Accept-Language: de,en;q=0.7,en-us;q=0.3" + "\r\n" +
      "\r\n"

    return request

  end

  def send_request(site,user_agent)

    begin
      connect

      request = write_request('GET',site,user_agent)
      sock.put(request)
      res = sock.get

      disconnect

      validcodes = datastore['ValidCode'].split(/,/)

      is_valid = 0
      retcode  = 0
      retvia   = 'n/a'
      retsrv   = 'n/a'

      if (res and res.match(/^HTTP\/1\.[01]\s+([^\s]+)\s+(.*)/))

        retcode = $1

        if (res.match(/Server: (.*)/))
          retsrv = $1.chomp
        end

        if (res.match(/Via: (.*)\((.*)\)/))
          retvia = $2
        end

        validcodes.each do |validcode|
          if (retcode.to_i == validcode.to_i)
            is_valid += 1
          end
        end

        if (check_pattern(res,datastore['ValidPattern']) == 1)
          is_valid += 1
        end
      end

      retres = [ is_valid, retcode, retvia, retsrv ]

      return retres

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end

  def send_request_ripe(user_agent)

    ripe_address = datastore['RIPE_ADDRESS']

    begin
      connect

      request = write_request('GET',ripe_address,user_agent)
      sock.put(request)
      res = sock.get

      disconnect

      retres = 0

      if (res and res.match(/^HTTP\/1\.[01]\s+([^\s]+)\s+(.*)/))

        retcode = $1

        if (retcode.to_i == 200)
          res.match(/Your IP Address is: <strong>(\s+)([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(\s+)<\/strong>/m)
          retres = "#{$2}.#{$3}.#{$4}.#{$5}"
        end
      end

      return retres

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end

  def check_host(target_host,target_port,site,user_agent)

    if datastore['DEBUG']
      print_status("Checking #{target_host}:#{target_port} [#{site}]")
    end

    is_valid,retcode,retvia,retsrv = send_request(site,user_agent)

    if (is_valid == 2)

      print_status("#{target_host}:#{target_port} is a potentially OPEN proxy [#{retcode}] (#{retvia})")

      report_note(
        :host   => target_host,
        :port   => target_port,
        :method => 'GET',
        :proto => 'tcp',
        :sname => (ssl ? 'https' : 'http'),
        :type  	=> 'OPEN PROXY',
        :data   => 'Open proxy'
      )

      if (datastore['VERIFY_CONNECT'])

        permit_connect,retcode,retvia,retsrv = send_request(site,user_agent)

        if (permit_connect == 2)
          print_status("#{target_host}:#{target_port} CONNECT method successfully tested")

          report_note(
            :host   => target_host,
            :port   => target_port,
            :method => 'CONNECT'
          )
        end
      end

      if (datastore['VERIFY_HEAD'])

        permit_connect,retcode,retvia,retsrv = send_request(site,user_agent)

        if (permit_connect == 2)
          print_status("#{target_host}:#{target_port} HEAD method successfully tested")

          report_note(
            :host   => target_host,
            :port   => target_port,
            :method => 'HEAD'
          )
        end
      end

      if (datastore['LOOKUP_PUBLIC_ADDRESS'])

        retres = send_request_ripe(user_agent)

        if (retres != 0)
          print_status("#{target_host}:#{target_port} using #{retres} public IP address")
        end
      end
    end

  end
end
