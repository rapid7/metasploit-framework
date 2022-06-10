# -*- coding: binary -*-

module Msf::Auxiliary::ManageengineXnode::Interact
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
    r_decoded = try_to_parse_json(r)
  end

  # JSON-parses an Xnode server response
  #
  # @param res [String] String containing a JSON hash with the Xnode server response
  # @return [Hash, Integer] Hash containing a JSON-parsed Xnode server response if interaction with the server succeeded, error code otherwise
  def try_to_parse_json(res)
    begin
      return JSON.parse(res)
    rescue StandardError => e
      print_error("Encountered the following error while trying to JSON parse the response from the Xnode server:\n#{e.to_s}")
      return 1
    end
  end
end
