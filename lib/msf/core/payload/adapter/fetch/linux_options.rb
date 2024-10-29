module Msf::Payload::Adapter::Fetch::LinuxOptions

  def initialize(info = {})
    super(update_info(info,
                      'DefaultOptions' => { 'FETCH_WRITABLE_DIR' => '/tmp' }
          ))
    register_options(
      [
        Msf::OptEnum.new('FETCH_COMMAND', [true, 'Command to fetch payload', 'CURL', %w{ CURL FTP TFTP TNFTP WGET }])
      ]
    )
  end
end