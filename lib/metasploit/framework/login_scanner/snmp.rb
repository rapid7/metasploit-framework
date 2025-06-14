# -*- coding: binary -*-

require 'snmp'
require 'metasploit/framework/login_scanner/base'

module Metasploit
  module Framework
    module LoginScanner
      # This is the LoginScanner class for dealing with SNMP.
      # It is responsible for taking a single target, and a list of credentials
      # and attempting them. It then saves the results.
      class SNMP
        include Metasploit::Framework::LoginScanner::Base

        DEFAULT_TIMEOUT = 2
        DEFAULT_PORT = 161
        DEFAULT_PROTOCOL = 'udp'.freeze
        DEFAULT_VERSION = '1'.freeze
        DEFAULT_QUEUE_SIZE = 100
        LIKELY_PORTS = [ 161, 162 ].freeze
        LIKELY_SERVICE_NAMES = [ 'snmp' ].freeze
        PRIVATE_TYPES = [ :password ].freeze
        REALM_KEY = nil

        attr_accessor :queued_credentials, :queued_results, :sock # :nodoc: # :nodoc: # :nodoc:

        # The SNMP version to scan
        # @return [String]
        attr_accessor :version

        # The SNMP protocol to use
        # @return [String]
        attr_accessor :protocol

        # The number of logins to try in each batch
        # @return [Integer]
        attr_accessor :queue_size

        validates :version,
                  presence: true,
                  inclusion: {
                    in: ['1', '2c', 'all']
                  }

        validates :protocol,
                  presence: true,
                  inclusion: {
                    in: ['udp', 'tcp']
                  }

        validates :queue_size,
                  presence: true,
                  numericality: {
                    only_integer: true,
                    greater_than_or_equal_to: 0
                  }

        # This method returns an array of versions to scan
        # @return [Array] An array of versions
        def versions
          case version
          when '1'
            [:SNMPv1]
          when '2c'
            [:SNMPv2c]
          when 'all'
            %i[SNMPv1 SNMPv2c]
          end
        end

        # Attempt to login with every {Credential credential} in # #cred_details.
        #
        # @yieldparam result [Result] The {Result} object for each attempt
        # @yieldreturn [void]
        # @return [void]
        def scan!
          valid!

          # Keep track of connection errors.
          # If we encounter too many, we will stop.
          consecutive_error_count = 0
          total_error_count = 0

          successful_users = Set.new
          first_attempt = true

          # Create a socket for the initial login tests (read-only)
          configure_socket

          # Create a map of community name to credential object
          credential_map = {}

          begin
            each_credential do |credential|
              # Track the credentials by community string
              credential_map[credential.public] = credential

              # Skip users for whom we've have already found a password
              if successful_users.include?(credential.public)
                # For Pro bruteforce Reuse and Guess we need to note that we
                # skipped an attempt.
                if credential.parent.respond_to?(:skipped)
                  credential.parent.skipped = true
                  credential.parent.save!
                end
                next
              end
              # Queue and trigger authentication if queue size is reached
              versions.each do |version|
                process_logins(community: credential.public, type: 'read', version: version)
              end

              # Exit early if we already have a positive result
              if stop_on_success && !queued_results.empty?
                break
              end
            end
          rescue Errno::ECONNREFUSED
            # Exit early if we get an ICMP port unreachable
            return
          end

          # Handle any unprocessed responses
          process_logins(final: true)

          # Create a non-duplicated set of credentials
          found_credentials = queued_results.uniq

          # Reset the queued results for our write test
          self.queued_results = []

          # Grab a new socket to avoid stale replies
          configure_socket

          # Try to write back the originally received values
          found_credentials.each do |result|
            process_logins(
              version: result[:snmp_version],
              community: result[:community],
              type: 'write',
              data: result[:proof]
            )
          end

          # Catch any stragglers
          process_logins(final: true)

          # Mark any results from our write scan as read-write in our found credentials
          queued_results.select { |r| [0, 17].include? r[:snmp_error] }.map { |r| r[:community] }.uniq.each do |c|
            found_credentials.select { |r| r[:community] == c }.each do |result|
              result[:access_level] = 'read-write'
            end
          end

          # Iterate the results
          found_credentials.each do |result_options|
            # Scrub the SNMP version & error code from the tracked result
            result_options.delete(:snmp_version)
            result_options.delete(:snmp_error)

            # Associate the community with the original credential
            result_options[:credential] = credential_map[result_options.delete(:community)]

            # In the rare chance that we got a result for a community we didn't scan...
            next unless result_options[:credential]

            # Create, freeze, and yield the result
            result = ::Metasploit::Framework::LoginScanner::Result.new(result_options)
            result.freeze
            yield result if block_given?
          end

          nil
        ensure
          shutdown_socket
        end

        # Queue up and possibly send any requests, based on the queue limit and final flag
        def process_logins(opts = {})
          self.queued_results ||= []
          self.queued_credentials ||= []

          unless opts[:final] || self.queued_credentials.length > queue_size
            self.queued_credentials.push [ opts[:type], opts[:community], opts[:version], opts[:data] ]
            return
          end

          return if self.queued_credentials.empty?

          process_responses(0.01)

          until self.queued_credentials.empty?
            action, community, version, data = self.queued_credentials.pop
            case action
            when 'read'
              send_snmp_read_request(version, community)
            when 'write'
              send_snmp_write_request(version, community, data)
            end
            sleep_between_attempts
          end
          process_responses(1.0)
        end

        def recv_wrapper(sock, max_size, timeout)
          res = nil
          if protocol == 'udp'
            res = sock.recvfrom(max_size, timeout)
          elsif protocol == 'tcp'
            ready = ::IO.select([sock], nil, nil, timeout)
            if ready
              res = sock.recv_nonblock(max_size)
              # Put into an array to mimic recvfrom
              res = [res, host, port]
            end
          end

          res
        end

        # Process any responses on the UDP socket and queue the results
        def process_responses(timeout = 1.0)
          queue = []
          while (res = recv_wrapper(sock, 65535, timeout))

            # Ignore invalid responses
            break if !(res[1])

            # Ignore empty responses
            next if !(res[0] && !res[0].empty?)

            # Trim the IPv6-compat prefix off if needed
            shost = res[1].sub(/^::ffff:/, '')

            response = parse_snmp_response(res[0])
            next unless response

            self.queued_results << {
              community: response[:community],
              host: host,
              port: port,
              protocol: protocol,
              service_name: 'snmp',
              proof: response[:proof],
              status: Metasploit::Model::Login::Status::SUCCESSFUL,
              access_level: 'read-only',
              snmp_version: response[:version],
              snmp_error: response[:error]
            }
          end
        end

        # Create and send a SNMP read request for sys.sysDescr.0
        def send_snmp_read_request(version, community)
          send_snmp_request(
            create_snmp_read_sys_descr_request(version, community)
          )
        end

        # Create and send a SNMP write request for sys.sysDescr.0
        def send_snmp_write_request(version, community, data)
          send_snmp_request(
            create_snmp_write_sys_descr_request(version, community, data)
          )
        end

        def send_wrapper(sock, pkt, host, port, flags)
          if protocol == 'tcp'
            return sock.send(pkt, flags)
          end

          if protocol == 'udp'
            return sock.sendto(pkt, host, port, 0)
          end
        end

        # Send a SNMP request on the existing socket
        def send_snmp_request(pkt)
          resend_count = 0

          begin
            send_wrapper(sock, pkt, host, port, 0)
          rescue ::Errno::ENOBUFS
            resend_count += 1
            if resend_count > MAX_RESEND_COUNT
              return false
            end

            ::IO.select(nil, nil, nil, 0.25)
            retry
          rescue ::Rex::ConnectionError
            # This fires for host unreachable, net unreachable, and broadcast sends
            # We can safely ignore all of these for UDP sends
          end
        end

        # Create a SNMP request that tries to read from sys.sysDescr.0
        def create_snmp_read_sys_descr_request(version_str, community)
          version = version_str == :SNMPv1 ? 1 : 2
          OpenSSL::ASN1::Sequence([
            OpenSSL::ASN1::Integer(version - 1),
            OpenSSL::ASN1::OctetString(community),
            OpenSSL::ASN1::Set.new([
              OpenSSL::ASN1::Integer(rand(0x80000000)),
              OpenSSL::ASN1::Integer(0),
              OpenSSL::ASN1::Integer(0),
              OpenSSL::ASN1::Sequence([
                OpenSSL::ASN1::Sequence([
                  OpenSSL::ASN1.ObjectId('1.3.6.1.2.1.1.1.0'),
                  OpenSSL::ASN1.Null(nil)
                ])
              ]),
            ], 0, :IMPLICIT)
          ]).to_der
        end

        # Create a SNMP request that tries to write to sys.sysDescr.0
        def create_snmp_write_sys_descr_request(version_str, community, data)
          version = version_str == :SNMPv1 ? 1 : 2
          snmp_write = OpenSSL::ASN1::Sequence([
            OpenSSL::ASN1::Integer(version - 1),
            OpenSSL::ASN1::OctetString(community),
            OpenSSL::ASN1::Set.new([
              OpenSSL::ASN1::Integer(rand(0x80000000)),
              OpenSSL::ASN1::Integer(0),
              OpenSSL::ASN1::Integer(0),
              OpenSSL::ASN1::Sequence([
                OpenSSL::ASN1::Sequence([
                  OpenSSL::ASN1.ObjectId('1.3.6.1.2.1.1.1.0'),
                  OpenSSL::ASN1::OctetString(data)
                ])
              ]),
            ], 3, :IMPLICIT)
          ]).to_der
        end

        # Parse a SNMP reply from a packet and return a response hash or nil
        def parse_snmp_response(pkt)
          asn = begin
            OpenSSL::ASN1.decode(pkt)
          rescue StandardError
            nil
          end
          return if !asn

          snmp_vers = begin
            asn.value[0].value.to_i
          rescue StandardError
            nil
          end
          snmp_comm = begin
            asn.value[1].value
          rescue StandardError
            nil
          end
          snmp_error = begin
            asn.value[2].value[1].value.to_i
          rescue StandardError
            nil
          end
          snmp_data = begin
            asn.value[2].value[3].value[0]
          rescue StandardError
            nil
          end
          snmp_oid = begin
            snmp_data.value[0].value
          rescue StandardError
            nil
          end
          snmp_info = begin
            snmp_data.value[1].value.to_s
          rescue StandardError
            nil
          end

          return if !(snmp_error && snmp_comm && snmp_data && snmp_oid && snmp_info)

          snmp_vers = snmp_vers == 0 ? '1' : '2c'

          { error: snmp_error, community: snmp_comm, proof: snmp_info, version: snmp_vers }
        end

        # Create a new socket for this scanner
        def configure_socket
          shutdown_socket if sock

          self.sock = ::Rex::Socket.create({
            'PeerHost' => host,
            'PeerPort' => port,
            'Proto' => protocol,
            'Timeout'  => connection_timeout,
            'Context' =>
              { 'Msf' => framework, 'MsfExploit' => framework_module }
          })
        end

        # Close any open socket if it exists
        def shutdown_socket
          sock.close if sock
          self.sock = nil
        end

        # Sets the SNMP parameters if not specified
        def set_sane_defaults
          self.connection_timeout = DEFAULT_TIMEOUT if connection_timeout.nil?
          self.protocol = DEFAULT_PROTOCOL if protocol.nil?
          self.port = DEFAULT_PORT if port.nil?
          self.version = DEFAULT_VERSION if version.nil?
          self.queue_size = DEFAULT_QUEUE_SIZE if queue_size.nil?
        end

      end
    end
  end
end
