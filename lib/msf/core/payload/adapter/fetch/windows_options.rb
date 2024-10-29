module Msf::Payload::Adapter::Fetch::WindowsOptions

  def initialize(info = {})
    super
    deregister_options('FETCH_WRITABLE_DIR')
    register_options(
      [
        Msf::OptEnum.new('FETCH_COMMAND', [true, 'Command to fetch payload', 'CURL', %w{ CURL TFTP CERTUTIL }]),
        Msf::OptString.new('FETCH_WRITABLE_DIR', [ true, 'Remote writable dir to store payload; cannot contain spaces.', '%TEMP%'], regex:/^[\S]*$/)
      ]
    )
  end
end
