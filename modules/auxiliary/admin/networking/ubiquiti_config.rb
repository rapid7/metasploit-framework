##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'zlib'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Ubiquiti
  include Msf::Exploit::Deprecated
  moved_from 'auxiliary/admin/ubiquiti/ubiquiti_config'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Ubiquiti Configuration Importer',
        'Description' => %q{
          This module imports an Ubiquiti device configuration.
          The db file within the .unf backup is the data file for
          Unifi. This module can take either the db file or .unf.
        },
        'License' => MSF_LICENSE,
        'Author' => ['h00die']
      )
    )

    register_options(
      [
        OptPath.new('CONFIG', [true, 'Path to configuration to import']),
        Opt::RHOST(),
        Opt::RPORT(22)
      ]
    )
  end

  def i_file
    datastore['CONFIG'].to_s
  end

  def run
    unless ::File.exist?(i_file)
      fail_with Failure::BadConfig, "Unifi config file #{i_file} does not exist!"
    end
    # input_file could be a unf (encrypted zip), or the db file contained within.
    input_file = ::File.open(i_file, 'rb')
    f = input_file.read
    input_file.close

    if f.nil?
      fail_with Failure::BadConfig, "#{i_file} read at 0 bytes.  Either file is empty or error reading."
    end

    if i_file.end_with? '.unf'
      decrypted_data = decrypt_unf(f)
      if decrypted_data.nil? || decrypted_data.empty?
        fail_with Failure::Unknown, 'Unable to decrypt'
      end
      print_good('File DECRYPTED.  Still needs to be repaired')
      loot_path = Rex::Quickfile.new('decrypted_zip.zip')
      loot_path.write(decrypted_data)
      loot_path.close
      # ruby zip can't repair, we can try on command line but its not likely to succeed on all platforms
      # tested on kali
      repaired = repair_zip(loot_path.path)
      if repaired.nil?
        fail_with Failure::Unknown, "Repair failed on #{loot_path.path}"
      end
      loot_path = Rex::Quickfile.new('fixed_zip.zip')
      loot_path.write(repaired)
      loot_path.close
      print_good("File DECRYPTED and REPAIRED and saved to #{loot_path.path}.")
      config_db = extract_and_process_db(loot_path.path)
      if config_db.nil?
        fail_with Failure::Unknown, 'Unable to locate db.gz config database file'
      end
      print_status('Converting BSON to JSON.')
      unifi_config_db_json = bson_to_json(config_db)
      if unifi_config_db_json == {}
        fail_with Failure::Unknown, 'Error in file conversion from BSON to JSON.'
      end
      unifi_config_eater(datastore['RHOSTS'], datastore['RPORT'], unifi_config_db_json)
      print_good('Config import successful')
    end
  end
end
