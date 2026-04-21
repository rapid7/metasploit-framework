###
#
# This mixin provides methods for interacting with Microsoft Active Directory
# Certificate Services
#
# -*- coding: binary -*-

require 'windows_error'
require 'windows_error/h_result'
require 'rex/proto/x509/request'

module Msf

module Exploit::Remote::MsIcpr

  include Msf::Exploit::Remote::SMB::Client::Ipc
  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::CertRequest
  include Msf::Exploit::Remote::LDAP::ActiveDirectory::AdCsOpts

  ADCS_CA_SERVICE_NAME = 'adcs-ca'

  class MsIcprError < StandardError; end
  class MsIcprConnectionError < MsIcprError; end
  class MsIcprAuthenticationError < MsIcprError; end
  class MsIcprAuthorizationError < MsIcprError; end
  class MsIcprNotFoundError < MsIcprError; end
  class MsIcprUnexpectedReplyError < MsIcprError; end
  class MsIcprUnknownError < MsIcprError; end

  def initialize(info = {})
    super

    register_options([
      OptString.new('CA', [ true, 'The target certificate authority' ]),
      Opt::RPORT(445)
    ], Msf::Exploit::Remote::MsIcpr)

  end

  def icpr_request_certificate(opts = {})
    tree = opts[:tree] || connect_ipc

    begin
      icpr = connect_icpr(tree)
    rescue RubySMB::Error::UnexpectedStatusCode => e
      if e.status_code == ::WindowsError::NTStatus::STATUS_OBJECT_NAME_NOT_FOUND
        # STATUS_OBJECT_NAME_NOT_FOUND will be the status if Active Directory Certificate Service (AD CS) is not installed on the target
        raise MsIcprNotFoundError, 'Connection failed (AD CS was not found).'
      end

      elog(e.message, error: e)
      raise MsIcprUnexpectedReplyError, "Connection failed (unexpected status: #{e.status_name})"
    end

    opts = opts.dup # Don't alter the caller's instance
    # Calls to this come from different places with different imports  and different opts hash values, so we need this
    # here to make sure all the data we need is populated
    opts[:username] = opts.fetch(:username) { datastore['SMBUser'] }
    opts[:domain] = opts.fetch(:domain) { simple.client.default_domain }
    opts[:service] = report_icertpassage_service

    with_adcs_certificate_request(opts) do |csr, attributes|
      do_request_cert(icpr, opts, csr, attributes)
    end

  rescue RubySMB::Dcerpc::Error::FaultError => e
    elog(e.message, error: e)
    raise MsIcprUnexpectedReplyError, "Operation failed (DCERPC fault: #{e.status_name})"
  rescue RubySMB::Dcerpc::Error::DcerpcError => e
    elog(e.message, error: e)
    raise MsIcprUnexpectedReplyError, e.message
  rescue RubySMB::Error::RubySMBError => e
    elog(e.message, error: e)
    raise MsIcprUnknownError, e.message
  end

  module_function

  def connect_icpr(tree)
    vprint_status('Connecting to ICertPassage (ICPR) Remote Protocol')
    icpr = tree.open_file(filename: 'cert', write: true, read: true)

    vprint_status('Binding to \\cert...')
    icpr.bind(
      endpoint: RubySMB::Dcerpc::Icpr,
      auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
      auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
    )
    vprint_good('Bound to \\cert')

    report_icertpassage_service

    icpr
  end

  def do_request_cert(icpr, opts, csr, attributes)
    response = icpr.cert_server_request(
      attributes: attributes,
      authority: datastore['CA'],
      csr: csr
    )
    case response[:status]
    when :issued
      print_good('The requested certificate was issued.')
    when :submitted
      print_warning('The requested certificate was submitted for review.')
    else
      print_error('There was an error while requesting the certificate.')
      print_error(response[:disposition_message].strip.to_s) unless response[:disposition_message].blank?
      hresult = ::WindowsError::HResult.find_by_retval(response[:disposition]).first

      if hresult
        print_error('Error details:')
        print_error("  Source:  #{hresult.facility}") if hresult.facility
        print_error("  HRESULT: #{hresult}")
      end

      case hresult
      when ::WindowsError::HResult::CERTSRV_E_ENROLL_DENIED
        raise MsIcprAuthorizationError.new(hresult.description)
      when ::WindowsError::HResult::CERTSRV_E_TEMPLATE_DENIED
        raise MsIcprAuthorizationError.new(hresult.description)
      when ::WindowsError::HResult::CERTSRV_E_UNSUPPORTED_CERT_TYPE
        raise MsIcprNotFoundError.new(hresult.description)
      else
        raise MsIcprUnknownError.new(hresult.description)
      end
    end

    response[:certificate]
  end

  def report_icertpassage_service
    report_service({
      name: 'icertpassage',
      resource: { dcerpc: { pipe: 'cert' } },
      host: simple.peerhost,
      port: simple.peerport,
      proto: 'tcp',
      parents: report_dcerpc_service
     })
  end
end
end
