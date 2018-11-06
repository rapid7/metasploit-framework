module RubySMB
  # Represents an SMB client capable of talking to SMB1 or SMB2 servers and handling
  # all end-user client functionality.
  class Client
    require 'ruby_smb/client/negotiation'
    require 'ruby_smb/client/authentication'
    require 'ruby_smb/client/signing'
    require 'ruby_smb/client/tree_connect'
    require 'ruby_smb/client/echo'
    require 'ruby_smb/client/utils'

    include RubySMB::Client::Negotiation
    include RubySMB::Client::Authentication
    include RubySMB::Client::Signing
    include RubySMB::Client::TreeConnect
    include RubySMB::Client::Echo
    include RubySMB::Client::Utils

    # The Default SMB1 Dialect string used in an SMB1 Negotiate Request
    SMB1_DIALECT_SMB1_DEFAULT = 'NT LM 0.12'.freeze
    # The Default SMB2 Dialect string used in an SMB1 Negotiate Request
    SMB1_DIALECT_SMB2_DEFAULT = 'SMB 2.002'.freeze
    # Dialect value for SMB2 Default (Version 2.02)
    SMB2_DIALECT_DEFAULT = 0x0202
    # The default maximum size of a SMB message that the Client accepts (in bytes)
    MAX_BUFFER_SIZE = 64512
    # The default maximum size of a SMB message that the Server accepts (in bytes)
    SERVER_MAX_BUFFER_SIZE = 4356

    # The dispatcher responsible for sending packets
    # @!attribute [rw] dispatcher
    #   @return [RubySMB::Dispatcher::Socket]
    attr_accessor :dispatcher

    # The domain you're trying to authenticate to
    # @!attribute [rw] domain
    #   @return [String]
    attr_accessor :domain

    # The local workstation to pretend to be
    # @!attribute [rw] local_workstation
    #   @return [String]
    attr_accessor :local_workstation

    # The NTLM client used for authentication
    # @!attribute [rw] ntlm_client
    #   @return [String]
    attr_accessor :ntlm_client

    # The password to authenticate with
    # @!attribute [rw] password
    #   @return [String]
    attr_accessor :password

    # The Native OS of the Peer/Server.
    # Currently only available with SMB1.
    # @!attribute [rw] peer_native_os
    #   @return [String]
    attr_accessor :peer_native_os

    # The Native LAN Manager of the Peer/Server.
    # Currently only available with SMB1.
    # @!attribute [rw] peer_native_lm
    #   @return [String]
    attr_accessor :peer_native_lm

    # The Primary Domain of the Peer/Server.
    # Currently only available with SMB1 and only when authentiation
    # without NTLMSSP is used.
    # @!attribute [rw] primary_domain
    #   @return [String]
    attr_accessor :primary_domain

    # The Netbios Name of the Peer/Server.
    # @!attribute [rw] default_name
    #   @return [String]
    attr_accessor :default_name

    # The Netbios Domain of the Peer/Server.
    # @!attribute [rw] default_domain
    #   @return [String]
    attr_accessor :default_domain

    # The Fully Qualified Domain Name (FQDN) of the computer.
    # @!attribute [rw] dns_host_name
    #   @return [String]
    attr_accessor :dns_host_name

    # The Fully Qualified Domain Name (FQDN) of the domain.
    # @!attribute [rw] dns_domain_name
    #   @return [String]
    attr_accessor :dns_domain_name

    # The Fully Qualified Domain Name (FQDN) of the forest.
    # @!attribute [rw] dns_tree_name
    #   @return [String]
    attr_accessor :dns_tree_name

    # The OS version number (<major>.<minor>.<build>) of the Peer/Server.
    # @!attribute [rw] os_version
    #   @return [String]
    attr_accessor :os_version

    # The negotiated dialect.
    # @!attribute [rw] dialect
    #   @return [Integer]
    attr_accessor :dialect

    # The Sequence Counter used for SMB1 Signing.
    # It tracks the number of packets both sent and received
    # since the NTLM session was initialized with the Challenge.
    # @!attribute [rw] sequence_counter
    #   @return [Integer]
    attr_accessor :sequence_counter

    # The current Session ID setup by authentication
    # @!attribute [rw] session_id
    #   @return [Integer]
    attr_accessor :session_id

    # Whether or not the Server requires signing
    # @!attribute [rw] signing_enabled
    #   @return [Boolean]
    attr_accessor :signing_required

    # Whether or not the Client should support SMB1
    # @!attribute [rw] smb1
    #   @return [Boolean]
    attr_accessor :smb1

    # Whether or not the Client should support SMB2
    # @!attribute [rw] smb2
    #   @return [Boolean]
    attr_accessor :smb2

    #  Tracks the current SMB2 Message ID that keeps communication in sync
    # @!attribute [rw] smb2_message_id
    #   @return [Integer]
    attr_accessor :smb2_message_id

    # The username to authenticate with
    # @!attribute [rw] username
    #   @return [String]
    attr_accessor :username

    # The UID set in SMB1
    # @!attribute [rw] user_id
    #   @return [String]
    attr_accessor :user_id

    # The maximum size SMB message that the Client accepts (in bytes)
    # The default value is equal to {MAX_BUFFER_SIZE}.
    # @!attribute [rw] max_buffer_size
    #   @return [Integer]
    attr_accessor :max_buffer_size

    # The maximum size SMB message that the Server accepts (in bytes)
    # The default value is small by default
    # @!attribute [rw] max_buffer_size
    #   @return [Integer]
    attr_accessor :server_max_buffer_size

    # The maximum size SMB2 write request that the Server accepts (in bytes)
    # @!attribute [rw] server_max_write_size
    #   @return [Integer]
    attr_accessor :server_max_write_size

    # The maximum size SMB2 read request that the Server accepts (in bytes)
    # @!attribute [rw] server_max_read_size
    #   @return [Integer]
    attr_accessor :server_max_read_size

    # The maximum size SMB2 transaction that the Server accepts (in bytes)
    # For transactions that are not a read or write request
    # @!attribute [rw] server_max_transact_size
    #   @return [Integer]
    attr_accessor :server_max_transact_size

    # @param dispatcher [RubySMB::Dispatcher::Socket] the packet dispatcher to use
    # @param smb1 [Boolean] whether or not to enable SMB1 support
    # @param smb2 [Boolean] whether or not to enable SMB2 support
    def initialize(dispatcher, smb1: true, smb2: true, username:, password:, domain: '.', local_workstation: 'WORKSTATION')
      raise ArgumentError, 'No Dispatcher provided' unless dispatcher.is_a? RubySMB::Dispatcher::Base
      if smb1 == false && smb2 == false
        raise ArgumentError, 'You must enable at least one Protocol'
      end
      @dispatcher        = dispatcher
      @domain            = domain
      @local_workstation = local_workstation
      @password          = password.encode('utf-8') || ''.encode('utf-8')
      @sequence_counter  = 0
      @session_id        = 0x00
      @session_key       = ''
      @signing_required  = false
      @smb1              = smb1
      @smb2              = smb2
      @username          = username.encode('utf-8') || ''.encode('utf-8')
      @max_buffer_size   = MAX_BUFFER_SIZE
      # These sizes will be modifed during negotiation
      @server_max_buffer_size = SERVER_MAX_BUFFER_SIZE
      @server_max_read_size   = RubySMB::SMB2::File::MAX_PACKET_SIZE
      @server_max_write_size  = RubySMB::SMB2::File::MAX_PACKET_SIZE
      @server_max_transact_size = RubySMB::SMB2::File::MAX_PACKET_SIZE

      negotiate_version_flag = 0x02000000
      flags = Net::NTLM::Client::DEFAULT_FLAGS |
        Net::NTLM::FLAGS[:TARGET_INFO] |
        negotiate_version_flag

      @ntlm_client = Net::NTLM::Client.new(
        @username,
        @password,
        workstation: @local_workstation,
        domain: @domain,
        flags: flags
      )

      @tree_connects = []
      @open_files = {}

      @smb2_message_id = 0
    end

    # Logs off any currently open session on the server
    # and closes the TCP socket connection.
    #
    # @return [void]
    def disconnect!
      begin
        logoff!
      rescue
        wipe_state!
      end
      dispatcher.tcp_socket.close
    end

    # Sends an Echo request to the server and returns the
    # NTStatus of the last response packet received.
    #
    # @param echo [Integer] the number of times the server should echo (ignored in SMB2)
    # @param data [String] the data the server should echo back (ignored in SMB2)
    # @return [WindowsError::ErrorCode] the NTStatus of the last response received
    def echo(count: 1, data: '')
      response = if smb2
                   smb2_echo
                 else
                   smb1_echo(count: count, data: data)
                 end
      response.status_code
    end

    # Sets the message id field in an SMB2 packet's
    # header to the one tracked by the client. It then increments
    # the counter on the client.
    #
    # @param packet [RubySMB::GenericPacket] the packet to set the message id for
    # @return [RubySMB::GenericPacket] the modified packet
    def increment_smb_message_id(packet)
      if packet.smb2_header.message_id.zero? && smb2_message_id != 0
        packet.smb2_header.message_id = smb2_message_id
        self.smb2_message_id += 1
      end
      packet
    end

    # Performs protocol negotiation and session setup. It defaults to using
    # the credentials supplied during initialization, but can take a new set of credentials if needed.
    def login(username: self.username, password: self.password, domain: self.domain, local_workstation: self.local_workstation)
      negotiate
      session_setup(username, password, domain, true,
                    local_workstation: local_workstation)
    end

    def session_setup(user, pass, domain, do_recv=true,
                      local_workstation: self.local_workstation)
      @domain            = domain
      @local_workstation = local_workstation
      @password          = pass.encode('utf-8') || ''.encode('utf-8')
      @username          = user.encode('utf-8') || ''.encode('utf-8')

      negotiate_version_flag = 0x02000000
      flags = Net::NTLM::Client::DEFAULT_FLAGS |
        Net::NTLM::FLAGS[:TARGET_INFO] |
        negotiate_version_flag

      @ntlm_client = Net::NTLM::Client.new(
          @username,
          @password,
          workstation: @local_workstation,
          domain: @domain,
          flags: flags
      )

      authenticate
    end

    # Sends a LOGOFF command to the remote server to terminate the session
    #
    # @return [WindowsError::ErrorCode] the NTStatus of the response
    # @raise [RubySMB::Error::InvalidPacket] if the response packet is not a LogoffResponse packet
    def logoff!
      if smb2
        request      = RubySMB::SMB2::Packet::LogoffRequest.new
        raw_response = send_recv(request)
        response     = RubySMB::SMB2::Packet::LogoffResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB2::SMB2_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB2::Packet::LogoffResponse::COMMAND,
            received_proto: response.smb2_header.protocol,
            received_cmd:   response.smb2_header.command
          )
        end
      else
        request      = RubySMB::SMB1::Packet::LogoffRequest.new
        raw_response = send_recv(request)
        response     = RubySMB::SMB1::Packet::LogoffResponse.read(raw_response)
        unless response.valid?
          raise RubySMB::Error::InvalidPacket.new(
            expected_proto: RubySMB::SMB1::SMB_PROTOCOL_ID,
            expected_cmd:   RubySMB::SMB1::Packet::LogoffResponse::COMMAND,
            received_proto: response.smb_header.protocol,
            received_cmd:   response.smb_header.command
          )
        end
      end
      wipe_state!
      response.status_code
    end

    # Sends a packet and receives the raw response through the Dispatcher.
    # It will also sign the packet if neccessary.
    #
    # @param packet [RubySMB::GenericPacket] the request to be sent
    # @return [String] the raw response data received
    def send_recv(packet)
      case packet.packet_smb_version
      when 'SMB1'
        packet.smb_header.uid = user_id if user_id
        packet = smb1_sign(packet)
      when 'SMB2'
        packet = increment_smb_message_id(packet)
        packet.smb2_header.session_id = session_id
        unless packet.is_a?(RubySMB::SMB2::Packet::SessionSetupRequest)
          packet = smb2_sign(packet)
        end
      else
        packet = packet
      end
      dispatcher.send_packet(packet)
      raw_response = dispatcher.recv_packet

      self.sequence_counter += 1 if signing_required && !session_key.empty?
      raw_response
    end

    # Connects to the supplied share
    #
    # @param share [String] the path to the share in `\\server\share_name` format
    # @return [RubySMB::SMB1::Tree] if talking over SMB1
    # @return [RubySMB::SMB2::Tree] if talking over SMB2
    def tree_connect(share)
      connected_tree = if smb2
        smb2_tree_connect(share)
      else
        smb1_tree_connect(share)
      end
      @tree_connects << connected_tree
      connected_tree
    end

    # Returns array of shares
    #
    # @return [Array] of shares
    # @param [String] host
    def net_share_enum_all(host)
      tree = tree_connect("\\\\#{host}\\IPC$")
      named_pipe = tree.open_file(filename: "srvsvc", write: true, read: true)
      named_pipe.net_share_enum_all(host)
    end

    # Resets all of the session state on the client, setting it
    # back to scratch. Should only be called when a session is no longer
    # valid.
    #
    # @return [void]
    def wipe_state!
      self.session_id       = 0x00
      self.user_id          = 0x00
      self.session_key      = ''
      self.sequence_counter = 0
      self.smb2_message_id  = 0
    end

    # Requests a NetBIOS Session Service using the provided name.
    #
    # @param name [String] the NetBIOS name to request
    # @return [TrueClass] if session request is granted
    # @raise [RubySMB::Error::NetBiosSessionService] if session request is refused
    # @raise [RubySMB::Error::InvalidPacket] if the response packet is not a NBSS packet
    def session_request(name = '*SMBSERVER')
      session_request = session_request_packet(name)
      dispatcher.send_packet(session_request, nbss_header: false)
      raw_response = dispatcher.recv_packet(full_response: true)
      begin
        session_header = RubySMB::Nbss::SessionHeader.read(raw_response)
        if session_header.session_packet_type == RubySMB::Nbss::NEGATIVE_SESSION_RESPONSE
          negative_session_response =  RubySMB::Nbss::NegativeSessionResponse.read(raw_response)
          raise RubySMB::Error::NetBiosSessionService, "Session Request failed: #{negative_session_response.error_msg}"
        end
      rescue IOError
        raise RubySMB::Error::InvalidPacket, 'Not a NBSS packet'
      end

      return true
    end

    # Crafts the NetBIOS SessionRequest packet to be sent for session request operations.
    #
    # @param name [String] the NetBIOS name to request
    # @return [RubySMB::Nbss::SessionRequest] the SessionRequest packet
    def session_request_packet(name = '*SMBSERVER')
      called_name = "#{name.upcase.ljust(15)}\x20"
      calling_name = "#{''.ljust(15)}\x00"

      session_request = RubySMB::Nbss::SessionRequest.new
      session_request.session_header.session_packet_type = RubySMB::Nbss::SESSION_REQUEST
      session_request.called_name  = called_name
      session_request.calling_name = calling_name
      session_request.session_header.packet_length =
        session_request.num_bytes - session_request.session_header.num_bytes
      session_request
    end

  end
end
