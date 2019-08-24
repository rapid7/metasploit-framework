##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/ubiquiti'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Ubiquiti
  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Ubiquiti Configuration Importer',
      'Description'   => %q{
        This module imports an Ubiquiti device configuration.
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

    if datastore['CONFIG'].end_with? ".unf"
      f = unifi_config.read
      if f.nil?
        print_error("#{full} read at 0 bytes.  Either file is empty or error reading.")
        return
      end
      decrypted_data = decrypt_unf(f)
      if decrypted_data.nil? || decrypted_data.empty?
        print_error('Unable to decrypt')
        return
      end
      print_good("File DECRYPTED.  Still needs to be repaired")
      loot_path = Rex::Quickfile.new("decrypted_zip")
      loot_path.write(decrypted_data)
      loot_path.close()
      # ruby zip can't repair, we can try on command line but its not likely to succeed on all platforms
      # tested on kali
      puts 'going to repair'
      repaired = repair_zip(loot_path.path)
      puts 'back'
      if repaired.nil?
        print_bad("Repair failed on #{loot_path}")
        return
      end
      loot_path = Rex::Quickfile.new("fixed_zip")
      loot_path.write(repaired)
      loot_path.close()
      print_good("File DECRYPTED and REPAIRED and saved to #{loot_path.path}.")
      Zip::File.open(loot_path) do |zip_file|
        # Handle entries one by one
        zip_file.each do |entry|
          # Extract to file/directory/symlink
          puts "Extracting #{entry.name}"
          #entry.extract(dest_file)

          # Read into memory
          #content = entry.get_input_stream.read
        end

        # Find specific entry
        #entry = zip_file.glob('*.csv').first
        #puts entry.get_input_stream.read
      end
      return
    end
    #else #db file
    #  uc_data = unifi_config.read
    #end

    print_status('Converting config BSON to JSON')
    unifi_config = bson_to_json(unifi_config.read)
    if unifi_config == {}
      print_bad('Error in conversion')
      return
    end
    unifi_config_eater(datastore['RHOSTS'],datastore['RPORT'],unifi_config)
    print_good('Config import successful')
  end
end



