#!/usr/bin/ruby

require 'Rex/Post/Process'
require 'Rex/Post/Meterpreter/Packet'
require 'Rex/Post/Meterpreter/Client'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

##
#
# Process
# -------
#
# This class implements the Rex::Post::Process interface.
#
##
class Process < Rex::Post::Process

	class <<self
		attr_accessor :client
	end

	# Gets the process id that the remote side is executing under
	def Process.getpid
		request = Packet.create_request('stdapi_process_getpid')

		response = client.send_request(request)

		return response.get_tlv_value(TLV_TYPE_PID)
	end

end

end; end; end; end; end
