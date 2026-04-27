module Msf::Payload::Adapter::Fetch::HTTP

  include Msf::Exploit::EXE
  include Msf::Payload::Adapter
  include Msf::Payload::Adapter::Fetch
  include Msf::Payload::Adapter::Fetch::Server::HTTP

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
      vprint_status("#{__method__}:#{__LINE__}")
      @fetch_service = start_http_fetch_handler(srvname)
      @srv_resources.each do |srv_entry|
        vprint_status("#{__method__}:#{__LINE__}")
        escaped_uri = ('/' + srv_entry[:uri]).gsub('//', '/')
        @myresources << escaped_uri
        add_resource(@fetch_service, escaped_uri, srv_entry)
        vprint_status("#{__method__}:#{__LINE__}")
      end
    end
    super
  end

end
