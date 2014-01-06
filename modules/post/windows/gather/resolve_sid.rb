##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Accounts

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather Local User Account SID Lookup',
        'Description'   => %q{ This module prints information about a given SID from the perspective of this session },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'chao-mu'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
    register_options(
      [
        OptString.new('SID', [ true, 'SID to lookup' ]),
        OptString.new('SYSTEM_NAME', [ false, 'Where to search. If undefined, first local then trusted DCs' ]),
      ], self.class)

  end

  def run
    sid = datastore['SID']
    target_system = datastore['SYSTEM_NAME']

    info = resolve_sid(sid, target_system ? target_system : nil)

    if info.nil?
      print_error 'Unable to resolve SID. Giving up.'
      return
    end

    sid_type = info[:type]

    if sid_type == :invalid
      print_error 'Invalid SID provided'
      return
    end

    unless info[:mapped]
      print_error 'No account found for the given SID'
      return
    end

    print_status "SID Type: #{sid_type.to_s}"
    print_status "Name:     #{info[:name]}"
    print_status "Domain:   #{info[:domain]}"
  end
end
