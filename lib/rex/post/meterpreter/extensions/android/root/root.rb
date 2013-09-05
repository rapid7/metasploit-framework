#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/android/tlv'
require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/client'
require 'rex/post/meterpreter/channels/pools/stream_pool'

module Rex
module Post
module Meterpreter
module Extensions
module Android
module Root


class Root

  def initialize(client)
    @client = client
  end

  def device_shutdown(n)
    request = Packet.create_request('device_shutdown')
    request.add_tlv(TLV_TYPE_SHUTDOWN_TIMER, n)
    response = client.send_request(request)
    return response.get_tlv(TLV_TYPE_SHUTDOWN_OK).value
  end  
  
  attr_accessor :client
end

end; 
end; 
end; 
end; 
end; 

end;