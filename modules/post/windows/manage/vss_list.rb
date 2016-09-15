##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'rex'

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::ShadowCopy

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Windows Manage List Shadow Copies",
      'Description'          => %q{
        This module will attempt to list any Volume Shadow Copies
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

    list = ""
    shadow_copies = vss_list
    unless shadow_copies.empty?
      shadow_copies.each do |copy|
        tbl = Rex::Text::Table.new(
          'Header'  => 'Shadow Copy Data',
          'Indent'  => 1,
          'Columns' => ['Field', 'Value']
        )
        copy.each_pair{|k,v| tbl << [k,v]}
        list << " #{tbl.to_s} \n\n"
        print_good tbl.to_s
      end
      store_loot(
          'host.shadowcopies',
          'text/plain',
          session,
          list,
          'shadowcopies.txt',
          'Shadow Copy Info'
      )
    end
  end

end
