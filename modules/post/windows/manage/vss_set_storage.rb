##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::ShadowCopy

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Windows Manage Set Shadow Copy Storage Space",
      'Description'          => %q{
        This module will attempt to change the ammount of space
        for volume shadow copy storage. This is based on the
        VSSOwn Script originally posted by Tim Tomes and
        Mark Baggett.

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
        OptInt.new('SIZE', [ true, 'Size in bytes to set for Max Storage'])
      ], self.class)

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
    if vss_set_storage(datastore['SIZE'])
      print_good("Size upated successfully")
    else
      print_error("There was a problem updating the storage size")
    end
  end



end
