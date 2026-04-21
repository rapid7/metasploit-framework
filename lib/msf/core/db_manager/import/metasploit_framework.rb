require 'msf/core/db_manager/import/marshal_validator'

module Msf::DBManager::Import::MetasploitFramework
  autoload :Credential, 'msf/core/db_manager/import/metasploit_framework/credential'
  autoload :XML, 'msf/core/db_manager/import/metasploit_framework/xml'
  autoload :Zip, 'msf/core/db_manager/import/metasploit_framework/zip'

  include Msf::DBManager::Import::MetasploitFramework::Credential
  include Msf::DBManager::Import::MetasploitFramework::XML
  include Msf::DBManager::Import::MetasploitFramework::Zip

  # Convert the string "NULL" to actual nil
  # @param [String] str
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
        marshalled_data = $1.unpack("m")[0]

        # Only attempt Marshal deserialization if the decoded data
        # starts with the Marshal version header (4.8). Otherwise
        # treat it as a plain string that happened to be base64-like.
        if Msf::DBManager::Import::MarshalValidator.marshalled_data?(marshalled_data)
          Msf::DBManager::Import::MarshalValidator.safe_load(marshalled_data, permitted_classes: %w[Time])
        else
          string
        end
      else
        if allow_yaml
          begin
            YAML.safe_load(string, permitted_classes: MetasploitDataModels::YAML::PERMITTED_CLASSES)
          rescue
            dlog("Badly formatted YAML: '#{string}'")
            string
          end
        else
          string
        end
      end
    rescue Msf::DBManager::Import::MarshalValidationError => e
      # Marshal validation failure indicates a potentially tampered export
      # file — abort the entire import rather than silently continuing.
      elem_name = xml_elem.respond_to?(:name) ? xml_elem.name : 'unknown'
      elem_path = xml_elem.respond_to?(:path) ? xml_elem.path : elem_name
      preview = string.length > 80 ? "#{string[0, 80]}..." : string
      raise Msf::DBImportError,
            "Unsafe deserialization blocked in <#{elem_name}> (#{elem_path}): " \
            "#{e.message} — base64 value: #{preview}"
    rescue ::Exception => e
      dlog("Failed to unserialize object: #{e.class} #{e.message}")
      if allow_yaml
        YAML.safe_load(string, permitted_classes: MetasploitDataModels::YAML::PERMITTED_CLASSES) rescue string
      else
        string
      end
    end
  end
end
