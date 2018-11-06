#
# Gems
#

require 'zip'

FactoryBot.define do
  factory :metasploit_credential_importer_zip,
          class: Metasploit::Credential::Importer::Zip do
    input { generate :metasploit_credential_importer_zip_file }
    origin {FactoryBot.build :metasploit_credential_origin_import }
  end



  # NB: There is not a very easy and time-effective way to DRY the below code.  These sequences define
  # zip files which represent valid and error-condition cases.

  #
  # Create a zip with keys and manifest,
  #
  sequence :metasploit_credential_importer_zip_file do |n|
    prefix = 'metasploit_credential_importer_zip_file'
    suffix = n.to_s
    path = Dir.mktmpdir([prefix, suffix])

    keys_path = "#{path}/#{Metasploit::Credential::Importer::Zip::KEYS_SUBDIRECTORY_NAME}"
    FileUtils.mkdir_p(keys_path)

    # Create keys
    key_data = 5.times.collect do
      FactoryBot.build(:metasploit_credential_ssh_key).data
    end

    # associate keys with usernames
    csv_hash = key_data.inject({}) do |hash, data|
      username = FactoryBot.generate(:metasploit_credential_public_username)
      hash[username] = data
      hash
    end

    # write out each key into a file in the intended zip directory
    csv_hash.each do |name, ssh_key_data|
      File.open("#{keys_path}/#{name}", 'w') do |file|
        file << ssh_key_data
      end
    end

    # write out manifest CSV into the zip directory
    # 'key' used twice because we are using usernames for filenames
    CSV.open("#{path}/#{Metasploit::Credential::Importer::Zip::MANIFEST_FILE_NAME}", 'wb') do |csv|
      csv << Metasploit::Credential::Importer::Core::VALID_LONG_CSV_HEADERS
      csv_hash.keys.each do |key|
        csv << [key, Metasploit::Credential::SSHKey.name, key, Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN, 'Rebels']
      end
    end

    # Write out zip file
    zip_location = "#{path}.zip"
    ::Zip::File.open(zip_location, ::Zip::File::CREATE) do |zipfile|
      Dir[File.join(path, '**', '**')].each do |file|
        zipfile.add(file.sub(path + '/', ''), file)
      end
    end

    File.open(zip_location, 'rb')
  end


  #
  # Create a zip without keys and WITH a manifest
  #
  sequence :metasploit_credential_importer_zip_file_invalid_no_keys do |n|
    prefix = 'metasploit_credential_importer_zip_file_invalid_no_keys'
    suffix = n.to_s
    path = Dir.mktmpdir([prefix, suffix])

    # Create keys
    key_data = 5.times.collect do
      FactoryBot.build(:metasploit_credential_ssh_key).data
    end

    # associate keys with usernames
    csv_hash = key_data.inject({}) do |hash, data|
      username = FactoryBot.generate(:metasploit_credential_public_username)
      hash[username] = data
      hash
    end

    # write out manifest CSV into the zip directory
    # 'key' used twice because we are using usernames for filenames
    CSV.open("#{path}/#{Metasploit::Credential::Importer::Zip::MANIFEST_FILE_NAME}", 'wb') do |csv|
      csv << Metasploit::Credential::Importer::Core::VALID_LONG_CSV_HEADERS
      csv_hash.keys.each do |key|
        csv << [key, Metasploit::Credential::SSHKey.name, key, Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN, 'Rebels']
      end
    end

    # Write out zip file
    zip_location = "#{path}.zip"
    ::Zip::File.open(zip_location, ::Zip::File::CREATE) do |zipfile|
      Dir[File.join(path, '**', '**')].each do |file|
        zipfile.add(file.sub(path + '/', ''), file)
      end
    end

    File.open(zip_location, 'rb')
  end


  #
  # Create a zip with keys and WITHOUT a manifest,
  #
  sequence :metasploit_credential_importer_zip_file_without_manifest do |n|
    prefix = 'metasploit_credential_importer_zip_file_without_manifest'
    suffix = n.to_s
    path = Dir.mktmpdir([prefix, suffix])

    keys_path = File.join(path, Metasploit::Credential::Importer::Zip::KEYS_SUBDIRECTORY_NAME)
    FileUtils.mkdir_p(keys_path)

    # Create keys
    key_data = 5.times.collect do
      FactoryBot.build(:metasploit_credential_ssh_key).data
    end

    # associate keys with usernames
    csv_hash = key_data.inject({}) do |hash, data|
      username = FactoryBot.generate(:metasploit_credential_public_username)
      hash[username] = data
      hash
    end

    # write out each key into a file in the intended zip directory
    csv_hash.each do |name, ssh_key_data|
      File.open("#{keys_path}/#{name}", 'w') do |file|
        file << ssh_key_data
      end
    end

    # Write out zip file
    zip_location = "#{path}.zip"
    ::Zip::File.open(zip_location, ::Zip::File::CREATE) do |zipfile|
      Dir[File.join(path, '**', '**')].each do |file|
        zipfile.add(file.sub(path + '/', ''), file)
      end
    end

    File.open(zip_location, 'rb')
  end
end

