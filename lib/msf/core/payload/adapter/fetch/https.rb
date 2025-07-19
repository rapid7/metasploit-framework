module Msf::Payload::Adapter::Fetch::Https

  include Msf::Exploit::EXE
  include Msf::Payload::Adapter
  include Msf::Payload::Adapter::Fetch
  include Msf::Payload::Adapter::Fetch::Server::Https

  def initialize(*args)
    super
  end

  def cleanup_handler
    if @fetch_service
      cleanup_http_fetch_service(@fetch_service, @myresources)
      @fetch_service = nil
    end

    super
  end

  def setup_handler
    unless datastore['FetchHandlerDisable']
      @fetch_service = start_https_fetch_handler(srvname)
      @srv_resources.each do |srv_data|
        escaped_uri = ('/' + srv_data[:uri]).gsub('//', '/')
        @myresources << escaped_uri
        add_resource(@fetch_service, escaped_uri, srv_data[:data])
      end
    end
    super
  end
end
