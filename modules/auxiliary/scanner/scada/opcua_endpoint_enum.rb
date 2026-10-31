# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  # Must come after Msf::Exploit::Remote::Tcp. A later include sits earlier in
  # the ancestor chain, so its initialize registers options after Tcp's has
  # returned, which is what lets Opt::RPORT(4840) replace the bare Opt::RPORT
  # that Tcp registers. Reverse the two and the default is lost silently.
  include Msf::Exploit::Remote::OpcUaClient

  # Shorthand for the library namespace, whose Enums name the values the
  # endpoints below are described with. Everything that speaks the protocol is
  # in Msf::Exploit::Remote::OpcUaClient; what is left here is the scan itself,
  # the shape the endpoints are reported in, and the judgment about which of
  # them are worth flagging.
  OpcUa = Rex::Proto::OpcUa

  # UserTokenType Anonymous (Part 4, section 7.42, Table 193).
  TOKEN_TYPE_ANONYMOUS = 0

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'OPC-UA Endpoint Enumeration',
        'Description' => %q{
          This module enumerates the endpoints advertised by an OPC-UA server
          over the OPC-UA TCP binary transport (opc.tcp://). It performs the
          connection handshake, opens a secure channel with SecurityPolicy=None,
          and calls the GetEndpoints service, which the specification requires to
          be available without authentication so that clients can discover how to
          connect.

          For each returned endpoint the module reports the advertised URL, the
          MessageSecurityMode, the SecurityPolicy, and the accepted user identity
          token types, along with the server's ApplicationUri and ProductUri as a
          fingerprint. Endpoints that accept anonymous identity over an
          unencrypted channel are flagged, as these allow an unauthenticated
          client to read and potentially write process data.

          No credentials are used and no address space operations are performed.
        },
        'Author' => [
          'Ethan Thomason <ethan@ethomason.com>'
        ],
        'References' => [
          ['URL', 'https://reference.opcfoundation.org/Core/Part4/'],
          ['URL', 'https://reference.opcfoundation.org/Core/Part6/'],
          ['URL', 'https://opcfoundation.org/about/opc-technologies/opc-ua/']
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
  end

  # ---------------------------------------------------------------------------
  # Presentation
  # ---------------------------------------------------------------------------

  # Flatten an EndpointDescription into the shape this module reports and files
  # in the database. The keys and their order are what report_note serializes
  # and what the module documentation describes, so they are part of the
  # module's interface rather than an implementation detail.
  #
  # @param endpoint [Rex::Proto::OpcUa::Services::EndpointDescription]
  # @return [Hash]
  def present(endpoint)
    server = endpoint.server
    name = server.application_name
    certificate = endpoint.server_certificate.snapshot
    mode = endpoint.security_mode.snapshot
    policy_uri = endpoint.security_policy_uri.snapshot

    {
      endpoint_url: endpoint.endpoint_url.snapshot,
      application_uri: server.application_uri.snapshot,
      product_uri: server.product_uri.snapshot,
      application_name: name.text? ? name.text.snapshot : nil,
      # The length rather than the certificate: the note goes to the database
      # and there is nothing to be learned from storing the whole blob.
      server_certificate_len: certificate.nil? ? 0 : certificate.bytesize,
      security_mode: mode,
      security_mode_name: OpcUa::Enums.security_mode_name(mode),
      security_policy_uri: policy_uri,
      security_policy_name: OpcUa::Enums.security_policy_name(policy_uri),
      user_tokens: endpoint.user_identity_tokens.map { |token| present_token(token) },
      security_level: endpoint.security_level.snapshot
    }
  end

  # @param token [Rex::Proto::OpcUa::Services::UserTokenPolicy]
  # @return [Hash]
  def present_token(token)
    token_type = token.token_type.snapshot

    {
      policy_id: token.policy_id.snapshot,
      token_type: token_type,
      token_type_name: OpcUa::Enums.user_token_type_name(token_type)
    }
  end

  # ---------------------------------------------------------------------------
  # Reporting
  # ---------------------------------------------------------------------------

  def unencrypted?(endpoint)
    endpoint[:security_mode_name] == 'None' || endpoint[:security_policy_name] == 'None'
  end

  def anonymous?(endpoint)
    endpoint[:user_tokens].any? { |t| t[:token_type] == TOKEN_TYPE_ANONYMOUS }
  end

  def report_endpoints(ip, endpoints)
    weak = endpoints.count { |ep| unencrypted?(ep) && anonymous?(ep) }

    print_good("OPC-UA server enumerated - #{endpoints.length} endpoint(s), #{weak} unauthenticated and unencrypted")

    fingerprint = endpoints.map { |ep| ep[:application_uri] }.compact.first
    product = endpoints.map { |ep| ep[:product_uri] }.compact.first

    endpoints.each_with_index do |ep, idx|
      security = "#{ep[:security_policy_name]}/#{ep[:security_mode_name]}"
      identity = ep[:user_tokens].map { |t| t[:token_type_name] }.uniq.join(', ')
      identity = 'none advertised' if identity.empty?

      print_status("  [#{idx}] #{ep[:endpoint_url]}")
      print_status("      security: #{security}  identity: #{identity}")

      if unencrypted?(ep) && anonymous?(ep)
        print_warning('      endpoint accepts anonymous clients over an unencrypted channel')
      end
    end

    print_status("  ApplicationUri: #{fingerprint}") if fingerprint
    print_status("  ProductUri: #{product}") if product

    info = "OPC-UA server, #{endpoints.length} endpoint(s)"
    info << ", ApplicationUri #{fingerprint}" if fingerprint

    report_service(
      host: ip,
      port: rport,
      proto: 'tcp',
      name: 'opc-ua',
      info: info
    )

    report_note(
      host: ip,
      port: rport,
      proto: 'tcp',
      type: 'opcua.endpoints',
      data: { endpoints: endpoints },
      update: :unique_data
    )

    return unless weak.positive?

    report_vuln(
      host: ip,
      port: rport,
      proto: 'tcp',
      name: 'OPC-UA endpoint accepting anonymous identity without encryption',
      info: "#{weak} of #{endpoints.length} advertised endpoint(s) accept the Anonymous user identity token over a channel with MessageSecurityMode None",
      refs: references
    )
  end

  # ---------------------------------------------------------------------------
  # Scanner entry point
  # ---------------------------------------------------------------------------

  def run_host(ip)
    connect

    stream = opcua_stream
    endpoint_url = "opc.tcp://#{Rex::Socket.to_authority(ip, rport)}"

    return unless hello_acknowledged?(stream, endpoint_url)

    vprint_good('OPC-UA Hello acknowledged, opening secure channel')

    token = open_secure_channel(stream)
    return if token.nil?

    # The client hands back the EndpointDescriptions as the library decoded
    # them. Which of their fields are worth showing, and what to make of them,
    # is this module's to decide.
    descriptions = enumerate_endpoints(stream, token, endpoint_url)
    return if descriptions.nil?

    endpoints = descriptions.map { |endpoint| present(endpoint) }

    if endpoints.empty?
      print_status('OPC-UA server returned no endpoints')
      return
    end

    report_endpoints(ip, endpoints)

    # Release the channel rather than leaving it open until its lifetime
    # expires. Nothing is read back; the scan is finished either way.
    begin
      send_close_secure_channel(stream, token)
    rescue ::Rex::ConnectionError, ::EOFError, ::Errno::ECONNRESET, ::Errno::EPIPE
      nil
    end
  # Every error the library raises descends from Rex::RuntimeError, and
  # Msf::Auxiliary::Scanner re-raises a bare ::RuntimeError out of its per host
  # loop rather than moving to the next host. One malformed server would
  # otherwise end a whole sweep, so the family is caught here as well as at each
  # step that expects it.
  rescue OpcUa::Error::OpcUaError => e
    vprint_error("OPC-UA transport error: #{e.message}")
  rescue ::Rex::ConnectionError, ::EOFError, ::Errno::ECONNRESET => e
    vprint_error("#{e.class}: #{e.message}")
  # A record that will not decode raises from BinData rather than from the
  # library. EOFError is an IOError, so it has to be caught above this.
  rescue ::BinData::ValidityError, ::IOError => e
    print_error("Malformed OPC-UA response: #{e.message}")
  ensure
    disconnect
  end
end
