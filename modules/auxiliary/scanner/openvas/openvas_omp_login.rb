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

  def initialize
  super(
    'Name'        => 'OpenVAS OMP Login Utility',
    'Description' => 'This module attempts to authenticate to an OpenVAS OMP service.',
    'Author'         => [ 'Vlatko Kosturjak <kost[at]linux.hr>' ],
    'License'        => MSF_LICENSE
  )
  register_options(
    [
      Opt::RPORT(9390),
      OptBool.new('BLANK_PASSWORDS', [false, "Try blank passwords for all users", false])
    ], self.class)

  register_advanced_options(
  [
    OptBool.new('SSL', [ true, "Negotiate SSL for outgoing connections", true]),
    OptString.new('SSLVersion', [ true, " Specify the version of SSL that should be used", "TLS1"])
  ], self.class)
  end

  def run_host(ip)
    begin
      print_status("#{msg} Connecting and checking username and passwords")
      each_user_pass do |user, pass|
        do_login(user, pass)
      end
    rescue ::Rex::ConnectionError
    rescue ::Exception => e
      vprint_error("#{msg} #{e.to_s} #{e.backtrace}")
    end
  end

  def omp_send(data=nil, con=true)
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
      print_error("#{msg} Error: #{err.to_s}")
    end
  end

  def do_login(user=nil,pass=nil)
    begin
      vprint_status("#{msg} Trying user:'#{user}' with password:'#{pass}'")
      cmd = "<authenticate><credentials><username>#{user}</username><password>#{pass}</password></credentials></authenticate><HELP/>\r\n"
      omp_send(cmd,true) # send hello
      if @result =~ /<authenticate_response.*status="200"/is
        print_good("#{msg} SUCCESSFUL login for '#{user}' : '#{pass}'")
        report_auth_info(
          :host => rhost,
          :port => rport,
          :sname => 'openvas-omp',
          :user => user,
          :pass => pass,
          :source_type => "user_supplied",
          :active => true
        )
        disconnect
        @connected = false
        return :next_user
      else
        if (@connected)
          disconnect # Sometime openvas disconnect the client after wrongs attempts
          @connected = false
        end
        vprint_error("#{msg} Rejected user: '#{user}' with password: '#{pass}': #{@result}")
        return :fail
      end
      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end

  def msg
    "#{rhost}:#{rport} OpenVAS OMP -"
  end
end
