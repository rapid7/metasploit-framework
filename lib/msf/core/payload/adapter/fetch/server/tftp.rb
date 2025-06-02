module Msf::Payload::Adapter::Fetch::Server::TFTP

  def start_tftp_server(srvport, srvhost)
    vprint_status("Starting TFTP server on #{Rex::Socket.to_authority(srvhost, srvport)}")
    Rex::Proto::TFTP::Server.new(srvport, srvhost, {})
  end

  def initialize(*args)
    super
    register_options(
      [
        Msf::OptBool.new('FETCH_SRVONCE', [ true, 'Stop serving the payload after it is retrieved', true ])
      ]
    )
  end
  def cleanup_tftp_fetch_service(fetch_service)
    fetch_service.stop
  end

  def add_resource(fetch_service, uri, srvexe)
    fetch_service.register_file(uri, srvexe, datastore['FETCH_SRVONCE'])
  end

  def fetch_protocol
    'TFTP'
  end

  def start_tftp_fetch_handler(srvport, srvhost)
    fetch_service = start_tftp_server(srvport, srvhost)
    if fetch_service.nil?
      cleanup_handler
      fail_with(Msf::Exploit::Failure::BadConfig, "Fetch handler failed to start on #{srvhost}:#{srvport}\n#{e}")
    end
    @srv_resources.each do |srv_data|
      escaped_uri = ('/' + srv_data[:uri]).gsub('//', '/')
      @myresources << escaped_uri
      add_resource(@fetch_service, escaped_uri, srv_data[:data])
    end
    fetch_service.start
    fetch_service
  end

end

