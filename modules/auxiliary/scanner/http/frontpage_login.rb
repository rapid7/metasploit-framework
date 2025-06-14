##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner


  def initialize
    super(
      'Name'        => 'FrontPage Server Extensions Anonymous Login Scanner',
      'Description' => 'This module queries the FrontPage Server Extensions and determines whether anonymous access is allowed.',
      'References'  =>
        [
          ['URL', 'https://en.wikipedia.org/wiki/Microsoft_FrontPage'],
          ['URL', 'https://docs.microsoft.com/en-us/previous-versions/office/developer/sharepoint-2010/ms454298(v=office.14)'],
        ],
      'Author'      => 'Matteo Cantoni <goony[at]nothink.org>',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('UserAgent', [ true, "The HTTP User-Agent sent in the request", Rex::UserAgent.session_agent ])
      ])
  end

  def run_host(target_host)

    if datastore['RPORT'].to_i == 80 or datastore['RPORT'].to_i == 443
      port = ""
    else
      port = ":" + datastore['RPORT'].to_s
    end

    info = (datastore['SSL'] ? "https" : "http") + "://#{target_host}#{port}/"

    connect

    sock.put("GET /_vti_inf.html HTTP/1.1\r\n" + "TE: deflate,gzip;q=0.3\r\n" + "Keep-Alive: 300\r\n" +
        "Connection: Keep-Alive, TE\r\n" + "Host: #{vhost}\r\n" + "User-Agent: " +
        datastore['UserAgent'] + "\r\n\r\n")

    res = sock.get_once || ''

    disconnect

    if (res.match(/HTTP\/1.1 200 OK/))
      if (res.match(/Server: (.*)/))
        server_version = $1
        print_status("#{info} is running #{server_version}")
      end
      if (fpversion = res.match(/FPVersion="(.*)"/))
        fpversion = $1
        print_status("#{info} FrontPage Version: #{fpversion}")

        if (fpauthor = res.match(/FPAuthorScriptUrl="([^"]*)/))
          fpauthor = $1
          print_status("#{info} FrontPage Author: #{info}#{fpauthor}")
          # Add Report
          opts = {
            :host  => target_host,
            :proto => 'tcp',
            :sname => (ssl ? 'https' : 'http'),
            :type  => 'FrontPage Author',
            :data  => { :author => "#{info}#{fpauthor}" }
          }
          opts[:port] = datastore['RPORT'] if not port.empty?
          report_note(opts)
        end
        check_account(info, fpversion, target_host)
      end
    else
      print_status("#{info} may not support FrontPage Server Extensions")
    end
  end

  def check_account(info, fpversion, target_host)

    return if not fpversion

    connect

    # https://docs.microsoft.com/en-us/previous-versions/office/developer/sharepoint-2010/ms454298(v=office.14)?redirectedfrom=MSDN
    method = "method=open+service:#{fpversion}&service_name=/"

    req = "POST /_vti_bin/_vti_aut/author.dll HTTP/1.1\r\n" + "TE: deflate,gzip;q=0.3\r\n" +
      "Keep-Alive: 300\r\n" + "Connection: Keep-Alive, TE\r\n" + "Host: #{vhost}\r\n" +
      "User-Agent: " + datastore['UserAgent'] + "\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" +
      "X-Vermeer-Content-Type: application/x-www-form-urlencoded" + "\r\n" +
      "Content-Length: #{method.length}\r\n\r\n" + method + "\r\n\r\n"

    sock.put(req)
    res = sock.get_once

    if(res and res.match(/^HTTP\/1\.[01]\s+([^\s]+)\s+(.*)/))
      retcode = $1
      retmsg  = $2.strip

      if(retcode == "100")
        ## Sometimes doesn't work !!!!!!!!!!!!!!!
        res = sock.get_once
        if(res and res.match(/^HTTP\/1\.[01]\s+([^\s]+)\s+(.*)/))
          retcode = $1
          retmsg  = $2.strip
        end
      end


      case retcode
        when /^200/
          print_good("#{info} FrontPage ACCESS ALLOWED [#{retcode}]")
          # Report a note or vulnerability or something
          # Not really this one, but close
          report_vuln(
            {
              :host   => target_host,
              :port	=> rport,
              :proto	=> 'tcp',
              :name	=> self.name,
              :info   => "Module #{self.fullname} confirmed access to #{info} [#{retcode}]",
              :refs   => self.references,
              :exploited_at => Time.now.utc
            }
          )
        when /^401/
          print_error("#{info} FrontPage Password Protected [#{retcode}]")
        when /^403/
          print_error("#{info} FrontPage Authoring Disabled [#{retcode}]")
        when /^404/
          print_error("#{info} FrontPage Improper Installation [#{retcode}]")
        when /^500/
          print_error("#{info} FrontPage Server Error [#{retcode}]")
        else
          print_error("#{info} FrontPage Unknown Response [#{retcode}]")
      end
    end

    disconnect
  end
end
