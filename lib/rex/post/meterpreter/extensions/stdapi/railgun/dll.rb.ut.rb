#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..','..','..','..','..', 'lib')) 

require 'rex/post/meterpreter/extensions/stdapi/railgun/dll'
require 'test/unit'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
class DLL::UnitTest < Test::Unit::TestCase

	TLV_TYPE_NAMES = {
		TLV_TYPE_RAILGUN_SIZE_OUT => "TLV_TYPE_RAILGUN_SIZE_OUT",
		TLV_TYPE_RAILGUN_STACKBLOB => "TLV_TYPE_RAILGUN_STACKBLOB",
		TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "TLV_TYPE_RAILGUN_BUFFERBLOB_IN", 
		TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT",
		TLV_TYPE_RAILGUN_DLLNAME => "TLV_TYPE_RAILGUN_DLLNAME",
		TLV_TYPE_RAILGUN_FUNCNAME => "TLV_TYPE_RAILGUN_FUNCNAME",
	}

	class MockRailgunClient
		attr_reader :platform, :check_request, :response_tlvs

		def initialize(platform, response_tlvs, check_request)
			@check_request = check_request
			@response_tlvs = response_tlvs
			@platform = platform 
		end

		def send_request(request)
			check_request.call(request)

			(Class.new do
				def initialize(response_tlvs)
					@response_tlvs = response_tlvs
				end
				def get_tlv_value(type)
					return @response_tlvs[type]
				end
			end).new(@response_tlvs)
		end
	end

	def make_mock_client(platform = "x86/win32", target_request_tlvs = [], response_tlvs = [])
		check_request = lambda do |request|
			target_request_tlvs.each_pair do |type, target_value|
				assert_equal(target_value, request.get_tlv_value(type),
					"process_function_call should send to client appropriate #{TLV_TYPE_NAMES[type]}")
			end
		end

		return  MockRailgunClient.new(platform, response_tlvs, check_request)
	end

	def test_add_function
		function_descriptions.each do |func|
			dll = DLL.new(func[:dll_name], make_mock_client(func[:platform]), nil)
			dll.add_function(func[:name], func[:return_type], func[:params])

			assert(dll.functions.has_key?(func[:name]),
				"add_function should expand the list of available functions")
		end
	end

	def test_method_missing
		function_descriptions.each do |func|
			client = make_mock_client(func[:platform], func[:request_to_client], func[:response_from_client])
			dll = DLL.new(func[:dll_name], client, nil)

			dll.add_function(func[:name], func[:return_type], func[:params])

			actual_returned_hash = dll.send(:method_missing, func[:name].to_sym, *func[:ruby_args])

			assert(func[:returned_hash].has_key?('GetLastError'),
				"process_function_call should add the result of GetLastError to the key GetLastError")

			assert_equal(func[:returned_hash], actual_returned_hash,
				"process_function_call convert function result to a ruby hash")
		end
	end

	# These are sample descriptions of functions to use for testing.
	def function_descriptions
		[
			{
				:platform => "x86/win32",
				:name => "LookupAccountSidA",
				:params => [
					["PCHAR","lpSystemName","in"],
					["LPVOID","Sid","in"],
					["PCHAR","Name","out"],
					["PDWORD","cchName","inout"],
					["PCHAR","ReferencedDomainName","out"],
					["PDWORD","cchReferencedDomainName","inout"],
					["PBLOB","peUse","out"],
				],
				:return_type => "BOOL",
				:dll_name => "advapi32",
				:ruby_args => [nil, 1371864, 100, 100, 100, 100, 1],
				:request_to_client => {
					TLV_TYPE_RAILGUN_SIZE_OUT => 201,
					TLV_TYPE_RAILGUN_STACKBLOB => "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xD8\xEE\x14\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00d\x00\x00\x00\x03\x00\x00\x00\b\x00\x00\x00\x02\x00\x00\x00\xC8\x00\x00\x00",
					TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "",
					TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "d\x00\x00\x00\x00\x00\x00\x00d\x00\x00\x00\x00\x00\x00\x00",
					TLV_TYPE_RAILGUN_DLLNAME => "advapi32",
					TLV_TYPE_RAILGUN_FUNCNAME => "LookupAccountSidA"
				},
				:response_from_client => {
					TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => "\x06\x00\x00\x00\x00\x00\x00\x00\f\x00\x00\x00\x00\x00\x00\x00",
					TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => "SYSTEM\x00AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANT AUTHORITY\x00AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x05",
					TLV_TYPE_RAILGUN_BACK_RET => 1,
					TLV_TYPE_RAILGUN_BACK_ERR => 997
				},
				:returned_hash => {
					"GetLastError" => 997,
					"return" => true,
					"Name" => "SYSTEM",
					"ReferencedDomainName" => "NT AUTHORITY",
					"peUse" => "\x05",
					"cchName" => 6,
					"cchReferencedDomainName" => 12
				},
			},
			{
				:platform => 'x64/win64',
				:name => 'LookupAccountSidA',
				:params => [
					["PCHAR", "lpSystemName", "in"],
					["LPVOID", "Sid", "in"],
					["PCHAR", "Name", "out"],
					["PDWORD", "cchName", "inout"],
					["PCHAR", "ReferencedDomainName", "out"],
					["PDWORD", "cchReferencedDomainName", "inout"],
					["PBLOB", "peUse", "out"]
				],
				:return_type => 'BOOL',
				:dll_name => 'advapi32',
				:ruby_args => [nil, 1631552, 100, 100, 100, 100, 1],
				:request_to_client => {
					TLV_TYPE_RAILGUN_SIZE_OUT => 201,
					TLV_TYPE_RAILGUN_STACKBLOB => "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\xE5\x18\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00d\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\b\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\xC8\x00\x00\x00\x00\x00\x00\x00",
					TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "",
					TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "d\x00\x00\x00\x00\x00\x00\x00d\x00\x00\x00\x00\x00\x00\x00",
					TLV_TYPE_RAILGUN_DLLNAME => 'advapi32',
					TLV_TYPE_RAILGUN_FUNCNAME => 'LookupAccountSidA',
				},
				:response_from_client => {
					TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => "\x06\x00\x00\x00\x00\x00\x00\x00\f\x00\x00\x00\x00\x00\x00\x00",
					TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => "SYSTEM\x00AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANT AUTHORITY\x00AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x05",
					TLV_TYPE_RAILGUN_BACK_RET => 1,
					TLV_TYPE_RAILGUN_BACK_ERR => 0,
				},
				:returned_hash => {
					"GetLastError"=>0,
					"return"=>true,
					"Name"=>"SYSTEM",
					"ReferencedDomainName"=>"NT AUTHORITY",
					"peUse"=>"\x05",
					"cchName"=>6,
					"cchReferencedDomainName"=>12
				},
			},
		]
	end
end
end
end
end
end
end
end
