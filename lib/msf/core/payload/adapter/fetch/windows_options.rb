module Msf::Payload::Adapter::Fetch::WindowsOptions

  def initialize(info = {})
    super
    register_options(
      [
        Msf::OptEnum.new('FETCH_COMMAND', [true, 'Command to fetch payload', 'CURL', %w{ CURL TFTP CERTUTIL }]),
        Msf::OptString.new('FETCH_FILENAME', [ false, 'Name to use on remote system when storing payload; cannot contain spaces or slashes', Rex::Text.rand_text_alpha(rand(8..12))], regex: %r{^[^\s/\\]*$}),
        Msf::OptString.new('FETCH_WRITABLE_DIR', [ true, 'Remote writable dir to store payload; cannot contain spaces.', '%TEMP%'], regex:/^[\S]*$/)
      ]
    )
  end
end
