# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/powershell/tlv'
require 'rex/post/meterpreter/extensions/powershell/command_ids'

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

  def self.extension_id
    EXTENSION_ID_POWERSHELL
  end

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

      request = Packet.create_request(COMMAND_ID_POWERSHELL_ASSEMBLY_LOAD)
      request.add_tlv(TLV_TYPE_POWERSHELL_ASSEMBLY_SIZE, binary.length)
      request.add_tlv(TLV_TYPE_POWERSHELL_ASSEMBLY, binary)
      client.send_request(request)
      return { loaded: true }
    end

    return { loaded: false }
  end

  def session_remove(opts={})
    return false unless opts[:session_id]
    request = Packet.create_request(COMMAND_ID_POWERSHELL_SESSION_REMOVE)
    request.add_tlv(TLV_TYPE_POWERSHELL_SESSIONID, opts[:session_id]) if opts[:session_id]
    client.send_request(request)
    return true
  end

  def execute_string(opts={})
    return nil unless opts[:code]

    request = Packet.create_request(COMMAND_ID_POWERSHELL_EXECUTE)
    request.add_tlv(TLV_TYPE_POWERSHELL_CODE, opts[:code])
    request.add_tlv(TLV_TYPE_POWERSHELL_SESSIONID, opts[:session_id]) if opts[:session_id]

    response = client.send_request(request)
    result = {}
    handle = client.sys.config.get_token_handle()
    if handle != 0
      result[:warning] = 'Impersonation will not apply to PowerShell.'
    end

    result[:output] = response.get_tlv_value(TLV_TYPE_POWERSHELL_RESULT)
    return result
  end

  def shell(opts={})
    request = Packet.create_request(COMMAND_ID_POWERSHELL_SHELL)
    request.add_tlv(TLV_TYPE_POWERSHELL_SESSIONID, opts[:session_id]) if opts[:session_id]

    response = client.send_request(request)
    channel_id = response.get_tlv_value(TLV_TYPE_CHANNEL_ID)
    if channel_id.nil?
      raise Exception, "We did not get a channel back!"
    end

    result = {}
    handle = client.sys.config.get_token_handle()
    if handle != 0
      result[:warning] = 'Impersonation will not apply to PowerShell.'
    end

    result[:channel] = Rex::Post::Meterpreter::Channels::Pools::StreamPool.new(client, channel_id, 'powershell_psh', CHANNEL_FLAG_SYNCHRONOUS, response)

    result
  end

end

end; end; end; end; end
