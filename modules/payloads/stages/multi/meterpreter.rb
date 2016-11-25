##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/base/sessions/meterpreter_multi'
require 'msf/base/sessions/meterpreter_options'
require 'rex/payloads/meterpreter/config'

###
#
# Injects the meterpreter server DLL via the Reflective Dll Injection payload
# along with transport related configuration.
#
###

module MetasploitModule

  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Architecture-Independent Meterpreter Stage',
      'Description'   => 'Handle Meterpreter sessions regardless of the target arch/platform',
      'Author'        => ['OJ Reeves'],
      'PayloadCompat' => {'Convention' => 'http'},
      'License'       => MSF_LICENSE,
      'Platform'      => ['win', 'osx', 'python', 'linux', 'android', 'java'],
      'Arch'          => [ARCH_X64, ARCH_X86, ARCH_JAVA, ARCH_PYTHON, ARCH_DALVIK],
      'Session'       => Msf::Sessions::Meterpreter_Multi))
  end

  def stage_payload(opts={})
    #return nil unless opts[:uuid]

    ## TODO: load the "stuff" from the JSON file?
    ## and if we find an instance, hydrate based on that.
    ## otherwise use some "sane defaults" as shown below.

    #c = Class.new(::Msf::Payload)
    #c.include(::Msf::Payload::Stager)

    #case opts[:uuid].platform
    #when 'python'
    #  require 'msf/core/payload/python/meterpreter_loader'
    #  c.include(::Msf::Payload::Python::MeterpreterLoader)
    #when 'java'
    #  require 'msf/core/payload/java/meterpreter_loader'
    #  c.include(::Msf::Payload::Java::MeterpreterLoader)
    #when 'php'
    #  require 'msf/core/payload/php/meterpreter_loader'
    #  c.include(::Msf::Payload::Php::MeterpreterLoader)
    #when 'windows'
    #  require 'msf/core/payload/windows/meterpreter_loader'
    #  if opts[:uuid].arch == ARCH_X86
    #    c.include(::Msf::Payload::Windows::MeterpreterLoader)
    #  else
    #    c.include(::Msf::Payload::Windows::MeterpreterLoader_x64)
    #  end
    #else
    #  return nil
    #end

    #second_stage = c.new()

    #second_stage.stage_meterpreter(opts) + generate_config(opts)
    ''
  end

  def generate_config(opts={})
    #ds = opts[:datastore] || datastore

    ## create the configuration block, which for staged connections is really simple.
    #config_opts = {
    #  arch:       opts[:uuid].arch,
    #  exitfunk:   ds['EXITFUNC'],
    #  expiration: ds['SessionExpirationTimeout'].to_i,
    #  uuid:       opts[:uuid],
    #  transports: [transport_config(opts)],
    #  extensions: []
    #}

    ## create the configuration instance based off the parameters
    #config = Rex::Payloads::Meterpreter::Config.new(config_opts)

    ## return the binary version of it
    #config.to_b
    ''
  end
end
