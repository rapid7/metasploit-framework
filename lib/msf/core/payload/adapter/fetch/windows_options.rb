module Msf::Payload::Adapter::Fetch::WindowsOptions

  def initialize(info = {})
    super(update_info(info,
                      'DefaultOptions' => { 'FETCH_WRITABLE_DIR' => '%TEMP%' }
          ))
    register_options(
      [
        Msf::OptEnum.new('FETCH_COMMAND', [true, 'Command to fetch payload', 'CURL', %w{ CURL TFTP CERTUTIL }])
      ]
    )
  end
end
