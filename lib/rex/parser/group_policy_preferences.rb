# -*- coding: binary -*-
#

module Rex
module Parser

# This is a parser for the Windows Group Policy Preferences file
# format. It's used by modules/post/windows/gather/credentials/gpp.rb
# and uses REXML (as opposed to Nokogiri) for its XML parsing.
# See: http://msdn.microsoft.com/en-gb/library/cc232587.aspx
class GPP
  require 'rex'
  require 'rexml/document'

  def self.parse(data)
    if data.nil?
      return []
    end

    xml = REXML::Document.new(data).root
    results = []

    unless xml and xml.elements and xml.elements.to_a("//Properties")
      return []
    end

    xml.elements.to_a("//Properties").each do |node|
      epassword = node.attributes['cpassword']
      next if epassword.to_s.empty?
      pass = self.decrypt(epassword)

      user = node.attributes['runAs'] if node.attributes['runAs']
      user = node.attributes['accountName'] if node.attributes['accountName']
      user = node.attributes['username'] if node.attributes['username']
      user = node.attributes['userName'] if node.attributes['userName']
      user = node.attributes['newName'] unless node.attributes['newName'].nil? or node.attributes['newName'].empty?
      changed = node.parent.attributes['changed']

      # Printers and Shares
      path = node.attributes['path']

      # Datasources
      dsn = node.attributes['dsn']
      driver = node.attributes['driver']

      # Tasks
      app_name = node.attributes['appName']

      # Services
      service = node.attributes['serviceName']

      # Groups
      expires = node.attributes['expires']
      never_expires = node.attributes['neverExpires']
      disabled = node.attributes['acctDisabled']

      result = {
        :USER => user,
        :PASS => pass,
        :CHANGED => changed
      }

      result.merge!({ :EXPIRES => expires }) unless expires.nil? or expires.empty?
      result.merge!({ :NEVER_EXPIRE => never_expires }) unless never_expires.nil? or never_expires.empty?
      result.merge!({ :DISABLED => disabled }) unless disabled.nil? or disabled.empty?
      result.merge!({	:PATH => path }) unless path.nil? or path.empty?
      result.merge!({ :DATASOURCE => dsn }) unless dsn.nil? or dsn.empty?
      result.merge!({ :DRIVER => driver }) unless driver.nil? or driver.empty?
      result.merge!({ :TASK => app_name }) unless app_name.nil? or app_name.empty?
      result.merge!({ :SERVICE => service }) unless service.nil? or service.empty?

      attributes = []
      node.elements.each('//Attributes//Attribute') do |dsn_attribute|
        attributes << {
          :A_NAME => dsn_attribute.attributes['name'],
          :A_VALUE => dsn_attribute.attributes['value']
        }
      end

      result.merge!({ :ATTRIBUTES => attributes }) unless attributes.empty?

      results << result
    end

    return results
  end

  def self.create_tables(results, filetype, domain=nil, dc=nil)
    tables = []
    results.each do |result|
      table = Rex::Ui::Text::Table.new(
        'Header'     => 'Group Policy Credential Info',
        'Indent'     => 1,
        'SortIndex'  => -1,
        'Columns'    =>
        [
          'Name',
          'Value',
        ]
      )

      table << ["TYPE", filetype]
      table << ["USERNAME", result[:USER]]
      table << ["PASSWORD", result[:PASS]]
      table << ["DOMAIN CONTROLLER", dc] unless dc.nil? or dc.empty?
      table << ["DOMAIN", domain] unless domain.nil? or domain.empty?
      table << ["CHANGED", result[:CHANGED]]
      table << ["EXPIRES", result[:EXPIRES]] unless result[:EXPIRES].nil? or result[:EXPIRES].empty?
      table << ["NEVER_EXPIRES?", result[:NEVER_EXPIRE]] unless result[:NEVER_EXPIRE].nil? or result[:NEVER_EXPIRE].empty?
      table << ["DISABLED", result[:DISABLED]] unless result[:DISABLED].nil? or result[:DISABLED].empty?
      table << ["PATH", result[:PATH]] unless result[:PATH].nil? or result[:PATH].empty?
      table << ["DATASOURCE", result[:DSN]] unless result[:DSN].nil? or result[:DSN].empty?
      table << ["DRIVER", result[:DRIVER]] unless result[:DRIVER].nil? or result[:DRIVER].empty?
      table << ["TASK", result[:TASK]] unless result[:TASK].nil? or result[:TASK].empty?
      table << ["SERVICE", result[:SERVICE]] unless result[:SERVICE].nil? or result[:SERVICE].empty?

      unless result[:ATTRIBUTES].nil? or result[:ATTRIBUTES].empty?
        result[:ATTRIBUTES].each do |dsn_attribute|
          table << ["ATTRIBUTE", "#{dsn_attribute[:A_NAME]} - #{dsn_attribute[:A_VALUE]}"]
        end
      end

      tables << table
    end

    return tables
  end

  # Decrypts passwords using Microsoft's published key:
  # http://msdn.microsoft.com/en-us/library/cc422924.aspx
  def self.decrypt(encrypted_data)
    unless encrypted_data
      return ""
    end
    
    pass = ""
    padding = "=" * (4 - (encrypted_data.length % 4))
    epassword = "#{encrypted_data}#{padding}"
    decoded = Rex::Text.decode_base64(epassword)

    key = "\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
    aes = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
    begin
      aes.decrypt
      aes.key = key
      plaintext = aes.update(decoded)
      plaintext << aes.final
      pass = plaintext.unpack('v*').pack('C*') # UNICODE conversion
    rescue OpenSSL::Cipher::CipherError => e
      puts "Unable to decode: \"#{encrypted_data}\" Exception: #{e}"
    end

    return pass
  end

end
end
end

