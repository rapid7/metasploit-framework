# -*- coding: binary -*-

module Msf::Auxiliary::ManageengineXnode::Interact
  # Create a socket to connect to an Xnode server and rescue any resulting errors
  #
  # @param rhost [String] Target IP
  # @param rport [Integer] Target port
  # @return [Array] Array containing of a response code (Integer) and either a Socket (when a connection is established) or an error message (String)
  def create_socket_for_xnode(rhost, rport)
    vprint_status('Attempting to establish a connection with the remote server...')
    begin
      sock = Rex::Socket::Tcp.create(
        'PeerHost' => rhost,
        'PeerPort' => rport
      )
    rescue => e
      vprint_status("Encountered the following exception type: #{e.class}")
      return [1, e.message]
    end

    vprint_status('Successfully connected to the remote server')
    [0, sock]
  end

  # Sends a request to an Xnode server
  #
  # @param sock [Socket] Socket to use for the request
  # @param action_hash [Hash] Hash containing an Xnode-compatible request
  # @return [Hash, Integer] Hash containing a JSON-parsed Xnode server response if interaction with the server succeeded, error code otherwise
  def send_to_sock(sock, action_hash)
    begin
      vprint_status("Sending request: #{action_hash}")

      sock.put(action_hash.to_json)
      # using sock.get for reading because the server doesn't send newlines so sock.read doesn't work
      # sock.recv won't work either since the message length can be (and often is) larger than the max of 65535
      r = sock.get
    rescue StandardError => e
      print_error("Encountered the following error while trying to interact with the Xnode server:\n#{e.to_s}")
      return 1
    end

    vprint_status("Received response: #{r}")

    # attempt to JSON parse the response
    begin
      return JSON.parse(r)
    rescue JSON::ParserError => e
      print_error("Encountered the following error while trying to JSON parse the response from the Xnode server:\n#{e.to_s}")
      return 1
    end
  end

  # Calls send_to_sock and performs basic checks on the received response to ensure it is valid
  #
  # @param sock [Socket] Socket to use for the request
  # @param action_hash [Hash] Hash containing an Xnode-compatible request
  # @param warning_messages [Array] Array of Strings print via print_warning if the server response doesn't match the expected format
  # @param expected_response_key [String] String that should be present as a key in the 'response' hash that is expected to be part of the JSON response
  # @return [Array, Integer] Array containing a response code and a JSON-parsed Xnode server response hash if interaction with the server succeeded, error code otherwise
  def get_response(sock, action_hash, warning_messages=[], expected_response_key=nil)
    res = send_to_sock(sock, action_hash)
    return 1 if res == 1

    unless res.instance_of?(Hash) && res.keys.include?('response') && res['response'].instance_of?(Hash)
      if expected_response_key
        unless res['response'].keys.include?(expected_response_key)
          warning_messages.each { |msg| print_warning(msg) }
          return [1, res]
        end
      else
        warning_messages.each { |msg| print_warning(msg) }
        return [1, res]
      end
    end

    [0, res]
  end
end
