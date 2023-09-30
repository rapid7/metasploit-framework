module Msf::Payload::Adapter::Fetch::Https

  include Msf::Exploit::EXE
  include Msf::Payload::Adapter
  include Msf::Payload::Adapter::Fetch
  include Msf::Payload::Adapter::Fetch::Server::Https

  def initialize(*args)
    super
  end

  def cleanup_handler
    cleanup_http_fetch_service(@fetch_service, @delete_resource)
    super
  end

  def setup_handler
    @fetch_service = start_https_fetch_handler(srvname, @srvexe) unless datastore['FetchHandlerDisable']
    super
  end

end