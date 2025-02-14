module Msf::Payload::Adapter::Fetch::LinuxOptions
  def initialize(info = {})
    super
    register_options(
      [
        Msf::OptEnum.new('FETCH_COMMAND', [true, 'Command to fetch payload', 'CURL', %w[CURL FTP TFTP TNFTP WGET]]),
        Msf::OptBool.new('FETCH_FILELESS', [true, 'Attempt to run payload without touching disk, Linux ≥3.17 only', false]),
        Msf::OptString.new('FETCH_FILENAME', [ false, 'Name to use on remote system when storing payload; cannot contain spaces or slashes', Rex::Text.rand_text_alpha(rand(8..12))], regex: %r{^[^\s/\\]*$}, conditions: ['FETCH_FILELESS', '==', 'false']),
        Msf::OptString.new('FETCH_WRITABLE_DIR', [ true, 'Remote writable dir to store payload; cannot contain spaces', '/tmp'], regex: /^\S*$/, conditions: ['FETCH_FILELESS', '==', 'false'])
      ]
    )
  end
end
