# Provides the server used by TFTP fetch payload adapters.
module Msf::Payload::Adapter::Fetch::Server::TFTP
  def initialize(*args)
    super
    register_options(
      [
        Msf::OptBool.new('FETCH_SRVONCE', [ true, 'Stop serving the payload after it is retrieved', true ])
      ]
    )
  end

  # Linux TFTP fetches always store the payload under its served URI. Since
  # LinuxOptions may register destination options after this mixin initializes,
  # remove them after each batch of options is registered.
  #
  # @param registered_options [Array<Msf::OptBase>] Options to register.
  # @param owner [Class] Class that owns the options.
  # @return [void]
  def register_options(registered_options, owner = self.class)
    super
    deregister_options('FETCH_FILENAME', 'FETCH_WRITABLE_DIR') if linux?
  end
  protected :register_options

  def cleanup_tftp_fetch_service(fetch_service)
    @myresources.each do |uri|
      fetch_service.deregister_file(uri)
    end
    @myresources = []
    fetch_service = nil
  end

  def fetch_protocol
    'TFTP'
  end

  def start_tftp_server(srvport, srvhost)
    vprint_status("Starting TFTP server on #{Rex::Socket.to_authority(srvhost, srvport)}")
    Rex::ServiceManager.start(
      Rex::Proto::TFTP::Server,
      srvport, srvhost,
      { 'Msf' => framework, 'MsfExploit' => self }
    )
  end

  def add_resource(fetch_service, uri, srv_entry)
    vprint_status("Adding TFTP resource #{uri}")
    fetch_service.register_file(uri, srv_entry[:data], datastore['FETCH_SRVONCE'])
    @myresources << uri
  end

  def start_tftp_fetch_handler(srvport, srvhost)
    fetch_service = start_tftp_server(srvport, srvhost)
    if fetch_service.nil?
      cleanup_handler
      fail_with(Msf::Exploit::Failure::BadConfig, "Fetch handler failed to start on #{Rex::Socket.to_authority(srvhost, srvport)}")
    end
    fetch_service
  end
end
