module Msf::DBManager::Import::MetasploitFramework
  require 'msf/core/db_manager/import/metasploit_framework/pwdump'
  include Msf::DBManager::Import::MetasploitFramework::Pwdump

  require 'msf/core/db_manager/import/metasploit_framework/xml'
  include Msf::DBManager::Import::MetasploitFramework::XML

  require 'msf/core/db_manager/import/metasploit_framework/zip'
  include Msf::DBManager::Import::MetasploitFramework::Zip

  # Convert the string "NULL" to actual nil
  def nils_for_nulls(str)
    str == "NULL" ? nil : str
  end

  def unserialize_object(xml_elem, allow_yaml = false)
    return nil unless xml_elem
    string = xml_elem.text.to_s.strip
    return string unless string.is_a?(String)
    return nil if (string.empty? || string.nil?)

    begin
      # Validate that it is properly formed base64 first
      if string.gsub(/\s+/, '') =~ /^([a-z0-9A-Z\+\/=]+)$/
        Marshal.load($1.unpack("m")[0])
      else
        if allow_yaml
          begin
            YAML.load(string)
          rescue
            dlog("Badly formatted YAML: '#{string}'")
            string
          end
        else
          string
        end
      end
    rescue ::Exception => e
      if allow_yaml
        YAML.load(string) rescue string
      else
        string
      end
    end
  end
end