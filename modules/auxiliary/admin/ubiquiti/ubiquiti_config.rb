##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'zlib'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Ubiquiti

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Ubiquiti Configuration Importer',
      'Description'   => %q{
        This module imports an Ubiquiti device configuration.
        The db file within the .unf backup is the data file for
        Unifi. This module can take either the db file or .unf.
        },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'h00die'],
      'Actions'       =>
        [
          ['UNIFI', {'Description' => 'Import Unifi .unf or db File'}],
        ],
      'DefaultAction' => 'UNIFI',
    ))

    register_options(
      [
        OptPath.new('CONFIG', [true, 'Path to configuration to import']),
        Opt::RHOST(),
        Opt::RPORT(22)
      ])

  end

  def run
    unless ::File.exist?(datastore['CONFIG'])
      fail_with Failure::BadConfig, "Unifi config file #{datastore['CONFIG']} does not exists!"
    end
    unifi_config = ::File.open(datastore['CONFIG'], "rb")
    f = unifi_config.read()
    unifi_config.close()

    if f.nil?
      print_error("#{full} read at 0 bytes.  Either file is empty or error reading.")
      return
    end

    if datastore['CONFIG'].end_with? ".unf"
      decrypted_data = decrypt_unf(f)
      if decrypted_data.nil? || decrypted_data.empty?
        print_error('Unable to decrypt')
        return
      end
      print_good("File DECRYPTED.  Still needs to be repaired")
      loot_path = Rex::Quickfile.new("decrypted_zip.zip")
      loot_path.write(decrypted_data)
      loot_path.close()
      # ruby zip can't repair, we can try on command line but its not likely to succeed on all platforms
      # tested on kali
      repaired = repair_zip(loot_path.path)
      if repaired.nil?
        print_bad("Repair failed on #{loot_path.path}")
        return
      end
      loot_path = Rex::Quickfile.new("fixed_zip.zip")
      loot_path.write(repaired)
      loot_path.close()
      print_good("File DECRYPTED and REPAIRED and saved to #{loot_path.path}.")
      Zip::File.open(loot_path.path) do |zip_file|
        # Handle entries one by one
        zip_file.each do |entry|
          # Extract to file
          if entry.name == 'db.gz'
            print_status('extracting db.gz')
            gz = Zlib::GzipReader.new(entry.get_input_stream)
            f = gz.read
            gz.close
            
          end
        end
      end
    end
    print_status('Converting config BSON to JSON')
    unifi_config = bson_to_json(f)
    if unifi_config == {}
      print_bad('Error in conversion')
      return
    end
    unifi_config_eater(datastore['RHOSTS'],datastore['RPORT'],unifi_config)
    print_good('Config import successful')
  end
end
