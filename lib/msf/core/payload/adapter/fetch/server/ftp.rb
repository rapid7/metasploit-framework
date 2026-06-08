# Mixin that provides FTP fetch handler support for fetch payload adapters.
module Msf::Payload::Adapter::Fetch::Server::FTP
  def initialize(*args)
    super
    register_options(
      [
        Msf::OptBool.new('FETCH_SRVONCE', [true, 'Stop serving the payload after it is retrieved', true]),

      ]
    )
  end

  def cleanup_ftp_fetch_service(fetch_service)
    @myresources.each do |uri|
      fetch_service.deregister_file(uri)
    end
    @myresources = []
    fetch_service = nil
  end

  def fetch_protocol
    'FTP'
  end

  def start_ftp_server(srvport, srvhost)
    vprint_status("Starting FTP server on #{Rex::Socket.to_authority(srvhost, srvport)}")
    Rex::ServiceManager.start(
      Rex::Proto::Ftp::Server,
      srvport, srvhost,
      { 'Msf' => framework, 'MsfExploit' => self }
    )
  end

  def add_resource(fetch_service, uri, srv_entry)
    vprint_status("Adding FTP resource #{uri}")
    fetch_service.register_file(uri, srv_entry[:data], serve_once: datastore['FETCH_SRVONCE'])
    @myresources << uri
  end

  def start_ftp_fetch_handler(srvport, srvhost)
    fetch_service = start_ftp_server(srvport, srvhost)
    if fetch_service.nil?
      cleanup_handler
      fail_with(Msf::Exploit::Failure::BadConfig, "Fetch handler failed to start on #{Rex::Socket.to_authority(srvhost, srvport)}")
    end
    fetch_service
  end
end
