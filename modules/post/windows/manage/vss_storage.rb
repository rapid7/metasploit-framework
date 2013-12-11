##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::ShadowCopy

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Windows Manage Get Shadow Copy Storage Info",
      'Description'          => %q{
        This module will attempt to get volume shadow copy storage info.
        This is based on the VSSOwn Script originally posted by
        Tim Tomes and Mark Baggett.

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

    storage_data = vss_get_storage
    if storage_data
      tbl = Rex::Ui::Text::Table.new(
          'Header'  => 'Shadow Copy Storage Data',
          'Indent'  => 1,
          'Columns' => ['Field', 'Value']
      )
      storage_data.each_pair{|k,v| tbl << [k,v]}
      print_good(tbl.to_s)
      store_loot(
          'host.shadowstorage',
          'text/plain',
          session,
          tbl.to_s,
          'shadowstorage.txt',
          'Shadow Copy Storage Info'
      )
    end
  end



end
