# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/lanattacks/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Lanattacks
module Tftp

###
#
# TFTP Server functionality
#
###
class Tftp

  def initialize(client)
    @client = client
  end

  def start
    client.send_request(Packet.create_request(COMMAND_ID_LANATTACKS_START_TFTP))
    true
  end

  def reset
    client.send_request(Packet.create_request(COMMAND_ID_LANATTACKS_RESET_TFTP))
    true
  end

  def add_file(filename, data)
    request = Packet.create_request(COMMAND_ID_LANATTACKS_ADD_TFTP_FILE)
    request.add_tlv(TLV_TYPE_LANATTACKS_OPTION_NAME, filename)
    request.add_tlv(TLV_TYPE_LANATTACKS_RAW, data, false, true) #compress it
    client.send_request(request)
    true
  end

  def stop
    client.send_request(Packet.create_request(COMMAND_ID_LANATTACKS_STOP_TFTP))
    true
  end

  attr_accessor :client
end

end; end; end; end; end; end
