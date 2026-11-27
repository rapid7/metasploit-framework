# -*- coding: binary -*-
# frozen_string_literal: true

# Enumerated values and identifiers from the OPC-UA specification.
#
# The numeric tables here are transcribed from the OPC Foundation's own
# machine-readable definitions rather than from prose, and can be re-verified
# against them:
#
#   StatusCodes  reference/opcua/StatusCode.csv
#   NodeIds      reference/opcua/NodeIds.csv
#
# Both are also published at
# https://github.com/OPCFoundation/UA-Nodeset/blob/latest/Schema/. Every value
# in this file has been checked against the local copies; note that
# StatusCode.csv spells the names without the underscore used here and in the
# specification prose, so Bad_TcpServerTooBusy is BadTcpServerTooBusy there.
module Rex::Proto::OpcUa::Enums
  # SecurityPolicy URI for the None policy. An endpoint offering this applies
  # no signing or encryption, so a channel opened under it is readable on the
  # wire and needs no key material from the client.
  NONE_POLICY_URI = 'http://opcfoundation.org/UA/SecurityPolicy#None'

  # Returned by the name lookups when a value is outside the enumeration.
  UNKNOWN_NAME = 'Unknown'

  # NodeId identifiers for the DefaultBinary encodings of the services used
  # over this transport. All are in namespace 0. A request and its response
  # differ by three, the intervening identifier being the XML encoding.
  #
  # All six were checked against reference/opcua/NodeIds.csv, where each appears
  # as <ServiceName>_Encoding_DefaultBinary. The OpenSecureChannel and
  # GetEndpoints response identifiers were also read back off the wire from the
  # captures in spec/file_fixtures/opc_ua.
  module NodeIds
    OPEN_SECURE_CHANNEL_REQUEST = 446
    OPEN_SECURE_CHANNEL_RESPONSE = 449
    CLOSE_SECURE_CHANNEL_REQUEST = 452
    CLOSE_SECURE_CHANNEL_RESPONSE = 455
    GET_ENDPOINTS_REQUEST = 428
    GET_ENDPOINTS_RESPONSE = 431
  end

  # MessageSecurityMode (Part 4, section 7.20, Table 139), matching the
  # enumeration of the same name in reference/opcua/Opc.Ua.Types.bsd.
  SECURITY_MODES = {
    0 => 'Invalid',
    1 => 'None',
    2 => 'Sign',
    3 => 'SignAndEncrypt'
  }.freeze

  # UserTokenType (Part 4, section 7.42, Table 193), matching the enumeration
  # of the same name in reference/opcua/Opc.Ua.Types.bsd.
  TOKEN_TYPES = {
    0 => 'Anonymous',
    1 => 'UserName',
    2 => 'Certificate',
    3 => 'IssuedToken'
  }.freeze

  # StatusCodes that may appear in an ERR response from the UA TCP transport,
  # or as the ServiceResult of a service that failed at the security layer.
  STATUS_CODES = {
    # The Connection Protocol error codes of Table 79 in OPC-UA Specification
    # Part 6, section 7.1.5. That table names the codes; their numeric values
    # are in Part 6 Annex A.2, and every one below was checked against
    # reference/opcua/StatusCode.csv.
    0x807D0000 => 'Bad_TcpServerTooBusy',
    0x807E0000 => 'Bad_TcpMessageTypeInvalid',
    0x807F0000 => 'Bad_TcpSecureChannelUnknown',
    0x80800000 => 'Bad_TcpMessageTooLarge',
    0x80810000 => 'Bad_TcpNotEnoughResources',
    0x80820000 => 'Bad_TcpInternalError',
    0x80830000 => 'Bad_TcpEndpointUrlInvalid',
    # Not in Table 79, but seen at this layer all the same.
    # Bad_ProtocolVersionUnsupported is named in the Hello Message text of
    # section 7.1.2.3; the rest arrive as the ServiceResult of a service that
    # failed at the security layer.
    0x80BE0000 => 'Bad_ProtocolVersionUnsupported',
    0x80130000 => 'Bad_SecurityChecksFailed',
    0x80120000 => 'Bad_CertificateInvalid',
    0x80840000 => 'Bad_RequestInterrupted',
    0x80850000 => 'Bad_RequestTimeout',
    0x80860000 => 'Bad_SecureChannelClosed',
    0x80870000 => 'Bad_SecureChannelTokenUnknown',
    0x80AC0000 => 'Bad_ConnectionRejected',
    0x80AE0000 => 'Bad_ConnectionClosed'
  }.freeze

  module_function

  # @param code [Integer] a StatusCode as it appears on the wire.
  # @return [String] the StatusCode name, or the value in hexadecimal when it
  #   is not one this table carries.
  def status_code_name(code)
    STATUS_CODES[code] || format('0x%08X', code)
  end

  # @param mode [Integer] a MessageSecurityMode value.
  # @return [String] the mode name, or Unknown with the value.
  def security_mode_name(mode)
    SECURITY_MODES[mode] || "#{UNKNOWN_NAME}(#{mode})"
  end

  # @param type [Integer] a UserTokenType value.
  # @return [String] the token type name, or Unknown with the value.
  def user_token_type_name(type)
    TOKEN_TYPES[type] || "#{UNKNOWN_NAME}(#{type})"
  end

  # Reduce a SecurityPolicy URI to the fragment that names the policy, so that
  # http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256 reports as
  # Basic256Sha256. A URI carrying no fragment is returned whole rather than
  # discarded, since an unrecognized policy is still worth reporting.
  #
  # @param uri [String, nil] a SecurityPolicyUri.
  # @return [String] the policy name.
  def security_policy_name(uri)
    return UNKNOWN_NAME if uri.nil? || uri.empty?

    uri.include?('#') ? uri.rpartition('#').last : uri
  end
end
