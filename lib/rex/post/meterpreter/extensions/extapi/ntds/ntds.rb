# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Extapi
module Ntds

###
#
# This meterpreter extension contains extended API functions for
# parsing the NT Directory Service database.
#
###
class Ntds

  def initialize(client)
    @client = client
  end

  def parse(filepath)
    request = Packet.create_request('extapi_ntds_parse')
    request.add_tlv( TLV_TYPE_NTDS_PATH, filepath)
    # wait up to 90 seconds for a response
    response = client.send_request(request, 90)
    channel_id = response.get_tlv_value(TLV_TYPE_CHANNEL_ID)
    if channel_id.nil?
      raise Exception, "We did not get a channel back!"
    end
    Rex::Post::Meterpreter::Channels::Pool.new(client, channel_id, "extapi_ntds", CHANNEL_FLAG_SYNCHRONOUS)
  end

  attr_accessor :client

end

end; end; end; end; end; end

