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
      @fetch_service = start_http_fetch_handler(srvname)
      escaped_uri = ('/' + srvuri).gsub('//', '/')
      add_resource(@fetch_service, escaped_uri, @srvexe)
      unless @pipe_uri.nil?
        uri = ('/' + @pipe_uri).gsub('//', '/')
        add_resource(@fetch_service, uri, @pipe_cmd)
      end
    end
    super
  end
end
