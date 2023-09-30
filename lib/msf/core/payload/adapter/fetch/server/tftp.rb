module Msf::Payload::Adapter::Fetch::Server::TFTP

  def start_tftp_server(srvport, srvhost)
    vprint_status("Starting TFTP server on #{srvhost}:#{srvport}")
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
    fetch_service.stop unless fetch_service.nil?
  end

  def fetch_protocol
    'TFTP'
  end

  def start_tftp_fetch_handler(srvport, srvhost, srvuri, srvexe)
    fetch_service = start_tftp_server(srvport, srvhost)
    if fetch_service.nil?
      cleanup_handler
      fail_with(Msf::Exploit::Failure::BadConfig, "Fetch Handler failed to start on #{srvhost}:#{srvport}\n #{e}")
    end
    fetch_service.register_file(srvuri, srvexe, datastore['FETCH_SRVONCE'])
    fetch_service.start
    fetch_service
  end

end

