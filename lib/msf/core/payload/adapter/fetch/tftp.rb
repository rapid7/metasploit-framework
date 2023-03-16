module Msf::Payload::Adapter::Fetch::TFTP

  include Msf::Exploit::EXE
  include Msf::Payload::Adapter
  include Msf::Payload::Adapter::Fetch
  include Msf::Payload::Adapter::Fetch::Server::TFTP

  def initialize(*args)
    super
  end

  def cleanup_handler
    cleanup_tftp_fetch_service(@fetch_service)
    super
  end

  def setup_handler
    @fetch_service = start_tftp_fetch_handler(fetch_bindport, fetch_bindhost, srvuri, @srvexe) unless datastore['FetchHandlerDisable']
    super
  end

end