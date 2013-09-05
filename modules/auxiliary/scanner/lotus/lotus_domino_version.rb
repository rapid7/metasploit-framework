##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Lotus Domino Version',
      'Description' => 'Several checks to determine Lotus Domino Server Version.',
      'Author'       => ['CG'],
      'License'     => MSF_LICENSE
      )
    register_options(
            [
              OptString.new('PATH', [ true,  "path", '/']),
            ] )
  end

  def run_host(ip)

    path = datastore['PATH']
    check1 = [
      'iNotes/Forms5.nsf',
      'iNotes/Forms6.nsf',
      'iNotes/Forms7.nsf',
      ]

    check2 = [
      'help/readme.nsf?OpenAbout'
      ]
    check3 = [
      'download/filesets/l_LOTUS_SCRIPT.inf',
      'download/filesets/n_LOTUS_SCRIPT.inf',
      'download/filesets/l_SEARCH.inf',
      'download/filesets/n_SEARCH.inf',
      ]

    currentversion = []
    baseversion = []

    begin

      check1.each do | check |

        res = send_request_raw({
          'uri'          =>  normalize_uri(path, check),
          'method'       => 'GET'
          }, 10)

        if (res.nil?)
          print_error("no response for #{ip}:#{rport} #{check}")
        elsif (res.code == 200 and res.body)
          #string we are regexing: <!-- Domino Release 7.0.3FP1 (Windows NT/Intel) -->
          if match = res.body.match(/\<!-- Domino Release(.*) --\>/);
            server1 = $1
            report_note(
              :host	=> ip,
              :proto => 'tcp',
              :sname => (ssl ? "https" : "http"),
              :port	=> rport,
              :type => 'lotusdomino.version.current',
              :data => server1.strip
                )
            if currentversion.empty? then
              currentversion << server1.strip
            elsif server1.strip == currentversion.last then
              ''
            else server1.strip != currentversion.last
              print_error("Different current version values") #this shouldnt happen,but just in case
              currentversion << ' : ' + server1.strip
            end
          else
            ''
          end
        elsif
          if (res.code and res.headers['Location'])
            print_error("#{ip}:#{rport} #{res.code} Redirect to #{res.headers['Location']}")
          else
            ''
          end
        else
          ''
        end
      end
      if currentversion.length == 0 then
        ''
      else
        print_status("#{ip}:#{rport} Lotus Domino Current Version: #{currentversion}")
      end

      check2.each do | check |

        res = send_request_raw({
          'uri'          =>  normalize_uri(path, check),
          'method'       => 'GET'
          }, 10)

        if (res.nil?)
          print_error("no response for #{ip}:#{rport} #{check}")
        elsif (res.code == 200 and res.body)
          #string we are regexing: <title>IBM Lotus Notes/Domino 6.5.6 Release Notes</title>
          if match = res.body.match(/\<title\>(.*)Lotus Notes\/Domino (.*) Release Notes\<\/title\>/);
            server2 = $2
            print_status("#{ip}:#{rport} Lotus Domino Release Notes Version: " + $2)
            report_note(
              :host	=> ip,
              :proto => 'tcp',
              :sname => (ssl ? "https" : "http"),
              :port	=> rport,
              :type => 'lotusdomino.version.releasenotes',
              :data => server2.strip
                )
          else
            ''
          end
        elsif
          if (res.code and res.headers['Location'])
            print_error("#{ip}:#{rport} #{res.code} Redirect to #{res.headers['Location']}")
          else
            ''
          end
        else
          ''
        end
      end

      check3.each do | check |

        res = send_request_raw({
          'uri'          =>  normalize_uri(path, check),
          'method'       => 'GET'
          }, 10)

        if (res.nil?)
          print_error("no response for #{ip}:#{rport} #{check}")
        elsif (res.code == 200 and res.body and res.body.index('TotalFileSize') and res.body.index('FileCount'))
          #string we are regexing: # Regex Version=8.5.1.0
          if match = res.body.match(/Version=(.*)/);
            server3 = $1
            report_note(
              :host	=> ip,
              :proto => 'tcp',
              :sname => (ssl ? "https" : "http"),
              :port	=> rport,
              :type => 'lotusdomino.version.base',
              :data => server3.strip
                )
            if baseversion.empty? then
              baseversion << server3.strip
            elsif server3.strip == baseversion.last then
              ''
            else server3.strip != baseversion.last #this shouldnt happen,but just in case
              print_error("Different base version values")
              baseversion << ' : ' + server3.strip
            end
          else
            ''
          end
        elsif
          if (res.code and res.headers['Location'])
            print_error("#{ip}:#{rport} #{res.code} Redirect to #{res.headers['Location']}")
          else
            ''
          end
        else
          ''
        end
      end
      if baseversion.length == 0 then
        ''
      else
        print_status("#{ip}:#{rport} Lotus Domino Base Install Version: #{baseversion}")
      end
    end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, Resolv::ResolvError, EOFError, Errno::ECONNABORTED, Errno::ECONNREFUSED, Errno::EHOSTUNREACH =>e
      print_error(e.message)
  end
end
