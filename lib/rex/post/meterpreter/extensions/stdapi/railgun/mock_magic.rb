# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun

require 'rex/post/meterpreter/extensions/stdapi/railgun/tlv'

#
# This mixin serves as a means of providing common mock objects and utilities
# relevant to railgun until a better home is decided upon
#
module MockMagic

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

  # These are sample descriptions of functions to use for testing.
  # the definitions include everything needed to mock and end to end test
  def mock_function_descriptions
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
      {
        :platform => 'x86/win32',
        :name => 'CryptAcquireContextW',
        :params => [["PDWORD", "phProv", "out"], ["PWCHAR", "pszContainer", "in"], ["PWCHAR", "pszProvider", "in"], ["DWORD", "dwProvType", "in"], ["DWORD", "dwflags", "in"]],
        :return_type => 'BOOL',
        :dll_name => 'advapi32',
        :ruby_args => [4, nil, "Microsoft Enhanced Cryptographic Provider v1.0", 1, 4026531840],
        :request_to_client => {
          TLV_TYPE_RAILGUN_SIZE_OUT => 4,
          TLV_TYPE_RAILGUN_STACKBLOB => "\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xF0",
          TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00 \x00E\x00n\x00h\x00a\x00n\x00c\x00e\x00d\x00 \x00C\x00r\x00y\x00p\x00t\x00o\x00g\x00r\x00a\x00p\x00h\x00i\x00c\x00 \x00P\x00r\x00o\x00v\x00i\x00d\x00e\x00r\x00 \x00v\x001\x00.\x000\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_DLLNAME => 'advapi32',
          TLV_TYPE_RAILGUN_FUNCNAME => 'CryptAcquireContextW',
        },
        :response_from_client => {
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => "\xC8\xEB\x14\x00",
          TLV_TYPE_RAILGUN_BACK_RET => 1,
          TLV_TYPE_RAILGUN_BACK_ERR => 0,
        },
        :returned_hash => {"GetLastError"=>0, "return"=>true, "phProv"=>1371080},
      },
      {
        :platform => 'x86/win32',
        :name => 'CryptCreateHash',
        :params => [["LPVOID", "hProv", "in"], ["DWORD", "Algid", "in"], ["LPVOID", "hKey", "in"], ["DWORD", "dwFlags", "in"], ["PDWORD", "phHash", "out"]],
        :return_type => 'BOOL',
        :dll_name => 'advapi32',
        :ruby_args => [1371080, 32771, 0, 0, 4],
        :request_to_client => {
          TLV_TYPE_RAILGUN_SIZE_OUT => 4,
          TLV_TYPE_RAILGUN_STACKBLOB => "\x00\x00\x00\x00\xC8\xEB\x14\x00\x00\x00\x00\x00\x03\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "",
          TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_DLLNAME => 'advapi32',
          TLV_TYPE_RAILGUN_FUNCNAME => 'CryptCreateHash',
        },
        :response_from_client => {
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => "p\xEA\x14\x00",
          TLV_TYPE_RAILGUN_BACK_RET => 1,
          TLV_TYPE_RAILGUN_BACK_ERR => 0,
        },
        :returned_hash => {"GetLastError"=>0, "return"=>true, "phHash"=>1370736},
      },
      {
        :platform => 'x86/win32',
        :name => 'CryptHashData',
        :params => [["LPVOID", "hHash", "in"], ["PWCHAR", "pbData", "in"], ["DWORD", "dwDataLen", "in"], ["DWORD", "dwFlags", "in"]],
        :return_type => 'BOOL',
        :dll_name => 'advapi32',
        :ruby_args => [1370736, "SmartFTP", 16, 0],
        :request_to_client => {
          TLV_TYPE_RAILGUN_SIZE_OUT => 0,
          TLV_TYPE_RAILGUN_STACKBLOB => "\x00\x00\x00\x00p\xEA\x14\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "S\x00m\x00a\x00r\x00t\x00F\x00T\x00P\x00\x00\x00\x00\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_DLLNAME => 'advapi32',
          TLV_TYPE_RAILGUN_FUNCNAME => 'CryptHashData',
        },
        :response_from_client => {
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => "",
          TLV_TYPE_RAILGUN_BACK_RET => 1,
          TLV_TYPE_RAILGUN_BACK_ERR => 0,
        },
        :returned_hash => {"GetLastError"=>0, "return"=>true},
      },
      {
        :platform => 'x86/win32',
        :name => 'CryptDeriveKey',
        :params => [["LPVOID", "hProv", "in"], ["DWORD", "Algid", "in"], ["LPVOID", "hBaseData", "in"], ["DWORD", "dwFlags", "in"], ["PDWORD", "phKey", "inout"]],
        :return_type => 'BOOL',
        :dll_name => 'advapi32',
        :ruby_args => [1371080, 26625, 1370736, 8388608, 4],
        :request_to_client => {
          TLV_TYPE_RAILGUN_SIZE_OUT => 0,
          TLV_TYPE_RAILGUN_STACKBLOB => "\x00\x00\x00\x00\xC8\xEB\x14\x00\x00\x00\x00\x00\x01h\x00\x00\x00\x00\x00\x00p\xEA\x14\x00\x00\x00\x00\x00\x00\x00\x80\x00\x03\x00\x00\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "",
          TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "\x04\x00\x00\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_DLLNAME => 'advapi32',
          TLV_TYPE_RAILGUN_FUNCNAME => 'CryptDeriveKey',
        },
        :response_from_client => {
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => "\xA0\x9C\x15\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => "",
          TLV_TYPE_RAILGUN_BACK_RET => 1,
          TLV_TYPE_RAILGUN_BACK_ERR => 0,
        },
        :returned_hash => {"GetLastError"=>0, "return"=>true, "phKey"=>1416352},
      },
      {
        :platform => 'x86/win32',
        :name => 'CryptDecrypt',
        :params => [["LPVOID", "hKey", "in"], ["LPVOID", "hHash", "in"], ["BOOL", "Final", "in"], ["DWORD", "dwFlags", "in"], ["PBLOB", "pbData", "inout"], ["PDWORD", "pdwDataLen", "inout"]],
        :return_type => 'BOOL',
        :dll_name => 'advapi32',
        :ruby_args => [1416352, 0, true, 0, "\x96\"\x83/\xCE|", 6],
        :request_to_client => {
          TLV_TYPE_RAILGUN_SIZE_OUT => 0,
          TLV_TYPE_RAILGUN_STACKBLOB => "\x00\x00\x00\x00\xA0\x9C\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\b\x00\x00\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "",
          TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "\x96\"\x83/\xCE|\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_DLLNAME => 'advapi32',
          TLV_TYPE_RAILGUN_FUNCNAME => 'CryptDecrypt',
        },
        :response_from_client => {
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => "q\x00u\x00x\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => "",
          TLV_TYPE_RAILGUN_BACK_RET => 1,
          TLV_TYPE_RAILGUN_BACK_ERR => 0,
        },
        :returned_hash => {"GetLastError"=>0, "return"=>true, "pbData"=>"q\x00u\x00x\x00", "pdwDataLen"=>6},
      },
      {
        :platform => 'x86/win32',
        :name => 'CryptDestroyHash',
        :params => [["LPVOID", "hHash", "in"]],
        :return_type => 'BOOL',
        :dll_name => 'advapi32',
        :ruby_args => [1370736],
        :request_to_client => {
          TLV_TYPE_RAILGUN_SIZE_OUT => 0,
          TLV_TYPE_RAILGUN_STACKBLOB => "\x00\x00\x00\x00p\xEA\x14\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "",
          TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_DLLNAME => 'advapi32',
          TLV_TYPE_RAILGUN_FUNCNAME => 'CryptDestroyHash',
        },
        :response_from_client => {
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => "",
          TLV_TYPE_RAILGUN_BACK_RET => 1,
          TLV_TYPE_RAILGUN_BACK_ERR => 0,
        },
        :returned_hash => {"GetLastError"=>0, "return"=>true},
      },
      {
        :platform => 'x86/win32',
        :name => 'CryptDestroyKey',
        :params => [["LPVOID", "hKey", "in"]],
        :return_type => 'BOOL',
        :dll_name => 'advapi32',
        :ruby_args => [1416352],
        :request_to_client => {
          TLV_TYPE_RAILGUN_SIZE_OUT => 0,
          TLV_TYPE_RAILGUN_STACKBLOB => "\x00\x00\x00\x00\xA0\x9C\x15\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "",
          TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_DLLNAME => 'advapi32',
          TLV_TYPE_RAILGUN_FUNCNAME => 'CryptDestroyKey',
        },
        :response_from_client => {
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => "",
          TLV_TYPE_RAILGUN_BACK_RET => 1,
          TLV_TYPE_RAILGUN_BACK_ERR => 0,
        },
        :returned_hash => {"GetLastError"=>0, "return"=>true},
      },
      {
        :platform => 'x86/win32',
        :name => 'CryptReleaseContext',
        :params => [["LPVOID", "hProv", "in"], ["DWORD", "dwFlags", "in"]],
        :return_type => 'BOOL',
        :dll_name => 'advapi32',
        :ruby_args => [1371080, 0],
        :request_to_client => {
          TLV_TYPE_RAILGUN_SIZE_OUT => 0,
          TLV_TYPE_RAILGUN_STACKBLOB => "\x00\x00\x00\x00\xC8\xEB\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "",
          TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_DLLNAME => 'advapi32',
          TLV_TYPE_RAILGUN_FUNCNAME => 'CryptReleaseContext',
        },
        :response_from_client => {
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => "",
          TLV_TYPE_RAILGUN_BACK_RET => 1,
          TLV_TYPE_RAILGUN_BACK_ERR => 0,
        },
        :returned_hash => {"GetLastError"=>0, "return"=>true},
      },
      {
        :platform => 'x64/win64',
        :name => 'CryptAcquireContextW',
        :params => [["PDWORD", "phProv", "out"], ["PWCHAR", "pszContainer", "in"], ["PWCHAR", "pszProvider", "in"], ["DWORD", "dwProvType", "in"], ["DWORD", "dwflags", "in"]],
        :return_type => 'BOOL',
        :dll_name => 'advapi32',
        :ruby_args => [8, nil, "Microsoft Enhanced Cryptographic Provider v1.0", 1, 4026531840],
        :request_to_client => {
          TLV_TYPE_RAILGUN_SIZE_OUT => 8,
          TLV_TYPE_RAILGUN_STACKBLOB => "\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xF0\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00 \x00E\x00n\x00h\x00a\x00n\x00c\x00e\x00d\x00 \x00C\x00r\x00y\x00p\x00t\x00o\x00g\x00r\x00a\x00p\x00h\x00i\x00c\x00 \x00P\x00r\x00o\x00v\x00i\x00d\x00e\x00r\x00 \x00v\x001\x00.\x000\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_DLLNAME => 'advapi32',
          TLV_TYPE_RAILGUN_FUNCNAME => 'CryptAcquireContextW',
        },
        :response_from_client => {
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => "\x80\xCE\x1A\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BACK_RET => 1,
          TLV_TYPE_RAILGUN_BACK_ERR => 0,
        },
        :returned_hash => {"GetLastError"=>0, "return"=>true, "phProv"=>1756800},
      },
      {
        :platform => 'x64/win64',
        :name => 'CryptCreateHash',
        :params => [["LPVOID", "hProv", "in"], ["DWORD", "Algid", "in"], ["LPVOID", "hKey", "in"], ["DWORD", "dwFlags", "in"], ["PDWORD", "phHash", "out"]],
        :return_type => 'BOOL',
        :dll_name => 'advapi32',
        :ruby_args => [1756800, 32771, 0, 0, 8],
        :request_to_client => {
          TLV_TYPE_RAILGUN_SIZE_OUT => 8,
          TLV_TYPE_RAILGUN_STACKBLOB => "\x00\x00\x00\x00\x00\x00\x00\x00\x80\xCE\x1A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "",
          TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_DLLNAME => 'advapi32',
          TLV_TYPE_RAILGUN_FUNCNAME => 'CryptCreateHash',
        },
        :response_from_client => {
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => "\x00\xA3\x19\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BACK_RET => 1,
          TLV_TYPE_RAILGUN_BACK_ERR => 0,
        },
        :returned_hash => {"GetLastError"=>0, "return"=>true, "phHash"=>1680128},
      },
      {
        :platform => 'x64/win64',
        :name => 'CryptHashData',
        :params => [["LPVOID", "hHash", "in"], ["PWCHAR", "pbData", "in"], ["DWORD", "dwDataLen", "in"], ["DWORD", "dwFlags", "in"]],
        :return_type => 'BOOL',
        :dll_name => 'advapi32',
        :ruby_args => [1680128, "SmartFTP", 16, 0],
        :request_to_client => {
          TLV_TYPE_RAILGUN_SIZE_OUT => 0,
          TLV_TYPE_RAILGUN_STACKBLOB => "\x00\x00\x00\x00\x00\x00\x00\x00\x00\xA3\x19\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "S\x00m\x00a\x00r\x00t\x00F\x00T\x00P\x00\x00\x00\x00\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_DLLNAME => 'advapi32',
          TLV_TYPE_RAILGUN_FUNCNAME => 'CryptHashData',
        },
        :response_from_client => {
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => "",
          TLV_TYPE_RAILGUN_BACK_RET => 1,
          TLV_TYPE_RAILGUN_BACK_ERR => 0,
        },
        :returned_hash => {"GetLastError"=>0, "return"=>true},
      },
      {
        :platform => 'x64/win64',
        :name => 'CryptDeriveKey',
        :params => [["LPVOID", "hProv", "in"], ["DWORD", "Algid", "in"], ["LPVOID", "hBaseData", "in"], ["DWORD", "dwFlags", "in"], ["PDWORD", "phKey", "inout"]],
        :return_type => 'BOOL',
        :dll_name => 'advapi32',
        :ruby_args => [1756800, 26625, 1680128, 8388608, 4],
        :request_to_client => {
          TLV_TYPE_RAILGUN_SIZE_OUT => 0,
          TLV_TYPE_RAILGUN_STACKBLOB => "\x00\x00\x00\x00\x00\x00\x00\x00\x80\xCE\x1A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01h\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xA3\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "",
          TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "\x04\x00\x00\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_DLLNAME => 'advapi32',
          TLV_TYPE_RAILGUN_FUNCNAME => 'CryptDeriveKey',
        },
        :response_from_client => {
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => "p\xA3\x19\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => "",
          TLV_TYPE_RAILGUN_BACK_RET => 1,
          TLV_TYPE_RAILGUN_BACK_ERR => 0,
        },
        :returned_hash => {"GetLastError"=>0, "return"=>true, "phKey"=>1680240},
      },
      {
        :platform => 'x64/win64',
        :name => 'CryptDecrypt',
        :params => [["LPVOID", "hKey", "in"], ["LPVOID", "hHash", "in"], ["BOOL", "Final", "in"], ["DWORD", "dwFlags", "in"], ["PBLOB", "pbData", "inout"], ["PDWORD", "pdwDataLen", "inout"]],
        :return_type => 'BOOL',
        :dll_name => 'advapi32',
        :ruby_args => [1680240, 0, true, 0, "\x85\"\x97/\xCC|", 6],
        :request_to_client => {
          TLV_TYPE_RAILGUN_SIZE_OUT => 0,
          TLV_TYPE_RAILGUN_STACKBLOB => "\x00\x00\x00\x00\x00\x00\x00\x00p\xA3\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\b\x00\x00\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "",
          TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "\x85\"\x97/\xCC|\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_DLLNAME => 'advapi32',
          TLV_TYPE_RAILGUN_FUNCNAME => 'CryptDecrypt',
        },
        :response_from_client => {
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => "b\x00a\x00z\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => "",
          TLV_TYPE_RAILGUN_BACK_RET => 1,
          TLV_TYPE_RAILGUN_BACK_ERR => 0,
        },
        :returned_hash => {"GetLastError"=>0, "return"=>true, "pbData"=>"b\x00a\x00z\x00", "pdwDataLen"=>6},
      },
      {
        :platform => 'x64/win64',
        :name => 'CryptDestroyHash',
        :params => [["LPVOID", "hHash", "in"]],
        :return_type => 'BOOL',
        :dll_name => 'advapi32',
        :ruby_args => [1680128],
        :request_to_client => {
          TLV_TYPE_RAILGUN_SIZE_OUT => 0,
          TLV_TYPE_RAILGUN_STACKBLOB => "\x00\x00\x00\x00\x00\x00\x00\x00\x00\xA3\x19\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "",
          TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_DLLNAME => 'advapi32',
          TLV_TYPE_RAILGUN_FUNCNAME => 'CryptDestroyHash',
        },
        :response_from_client => {
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => "",
          TLV_TYPE_RAILGUN_BACK_RET => 1,
          TLV_TYPE_RAILGUN_BACK_ERR => 0,
        },
        :returned_hash => {"GetLastError"=>0, "return"=>true},
      },
      {
        :platform => 'x64/win64',
        :name => 'CryptDestroyKey',
        :params => [["LPVOID", "hKey", "in"]],
        :return_type => 'BOOL',
        :dll_name => 'advapi32',
        :ruby_args => [1680240],
        :request_to_client => {
          TLV_TYPE_RAILGUN_SIZE_OUT => 0,
          TLV_TYPE_RAILGUN_STACKBLOB => "\x00\x00\x00\x00\x00\x00\x00\x00p\xA3\x19\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "",
          TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_DLLNAME => 'advapi32',
          TLV_TYPE_RAILGUN_FUNCNAME => 'CryptDestroyKey',
        },
        :response_from_client => {
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => "",
          TLV_TYPE_RAILGUN_BACK_RET => 1,
          TLV_TYPE_RAILGUN_BACK_ERR => 0,
        },
        :returned_hash => {"GetLastError"=>0, "return"=>true},
      },
      {
        :platform => 'x64/win64',
        :name => 'CryptReleaseContext',
        :params => [["LPVOID", "hProv", "in"], ["DWORD", "dwFlags", "in"]],
        :return_type => 'BOOL',
        :dll_name => 'advapi32',
        :ruby_args => [1756800, 0],
        :request_to_client => {
          TLV_TYPE_RAILGUN_SIZE_OUT => 0,
          TLV_TYPE_RAILGUN_STACKBLOB => "\x00\x00\x00\x00\x00\x00\x00\x00\x80\xCE\x1A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
          TLV_TYPE_RAILGUN_BUFFERBLOB_IN => "",
          TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_DLLNAME => 'advapi32',
          TLV_TYPE_RAILGUN_FUNCNAME => 'CryptReleaseContext',
        },
        :response_from_client => {
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => "",
          TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => "",
          TLV_TYPE_RAILGUN_BACK_RET => 1,
          TLV_TYPE_RAILGUN_BACK_ERR => 0,
        },
        :returned_hash => {"GetLastError"=>0, "return"=>true},
      },
    ]
  end

end

end; end; end; end; end; end;
