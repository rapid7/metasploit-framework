module Msf::Payload::Adapter::Fetch::TFTP

  include Msf::Exploit::EXE
  include Msf::Payload::Adapter
  include Msf::Payload::Adapter::Fetch
  include Msf::Payload::Adapter::Fetch::Server::TFTP

  def initialize(*args)
    super
  end

  def cleanup_handler
    if @fetch_service
      cleanup_tftp_fetch_service(@fetch_service)
      @fetch_service = nil
    end

    super
  end

  def setup_handler
    unless datastore['FetchHandlerDisable']
      @fetch_service = start_tftp_server(fetch_bindport, fetch_bindhost)
      @srv_resources.each do |srv_data|
        @myresources << srv_data[:uri]
        add_resource(@fetch_service, srv_data[:uri], srv_data[:data])
      end
    end
    @fetch_service.start
    super
  end

end
