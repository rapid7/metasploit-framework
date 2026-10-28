# Mixin for fetch payloads that retrieve and execute a stage over FTP.
module Msf::Payload::Adapter::Fetch::FTP
  include Msf::Exploit::EXE
  include Msf::Payload::Adapter
  include Msf::Payload::Adapter::Fetch
  include Msf::Payload::Adapter::Fetch::Server::FTP

  def initialize(*args)
    super
  end

  def cleanup_handler
    if @fetch_service
      cleanup_ftp_fetch_service(@fetch_service)
      @fetch_service = nil
    end

    super
  end

  def setup_handler
    unless datastore['FetchHandlerDisable']
      @fetch_service = start_ftp_fetch_handler(fetch_bindport, fetch_bindhost)
      @srv_resources.each do |srv_entry|
        add_resource(@fetch_service, srv_entry[:uri], srv_entry)
      end
    end
    super
  end
end
