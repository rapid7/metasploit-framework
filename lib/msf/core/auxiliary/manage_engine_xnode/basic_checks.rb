# -*- coding: binary -*-

module Msf::Auxiliary::ManageEngineXnode::BasicChecks
  include Msf::Auxiliary::ManageEngineXnode::Action
  include Msf::Auxiliary::ManageEngineXnode::Interact
  # Performs a sanity check and an authentication attempt against Xnode to verify if the target is Xnode and if we can authenticate
  #
  # @param sock [Socket] Socket to use for the request
  # @param username [String] Username
  # @param password [String] Password
  # @return [Array] Array containing a response code (Integer) and a status message (String)
  def xnode_check(sock, username, password)
    res_code, res_msg = xnode_sanity_check(sock)
    if res_code != 0
      return [res_code, res_msg]
    end

    print_status(res_msg)
    xnode_authenticate(sock, username, password)
  end

  # Checks if a target is likely Xnode by sending an empty JSON hash and parsing the response
  #
  # @param sock [Socket] Socket to use for the request
  # @return [Array] Array containing a response code (Integer) and a status message (String)
  def xnode_sanity_check(sock)
    # sanity check: send empty request to see if we get the expected `Authentication failed!` response
    vprint_status('Attempting to verify if the target is Xnode by sending an empty JSON hash')
    res = send_to_sock(sock, {})
    unless res.instance_of?(Hash) && res.keys.include?('response') && res['response'].instance_of?(Hash) && res['response'].include?('error_msg')
      return [2, 'Received unexpected response. The target does not seem to be an Xnode server.']
    end

    error_msg = res['response']['error_msg']
    case error_msg
    when 'Authentication failed!'
      return [0, 'Target seems to be Xnode.']
    when 'Remote request-processing disabled!!'
      return [1, 'Target is Xnode, but remote request-processing is disabled.']
    else
      return [2, "Received the following unexpected error message from Xnode: #{error_msg}"]
    end
  end

  # Performs an Xnode authentication attempt and parses the response
  #
  # @param sock [Socket] Socket to use for the request
  # @param username [String] Username
  # @param password [String] Password
  # @return [Array] Array containing a response code (Integer) and a status message (String)
  def xnode_authenticate(sock, username, password)
    res = send_to_sock(sock, action_authenticate(username, password))

    unless res.instance_of?(Hash) && res.keys.include?('response') && res['response'].instance_of?(Hash)
      return [2, 'Received unexpected response when trying to authenticate.']
    end

    if res['response']['status'] == 'authentication_success'
      return [0, 'Successfully authenticated to the Xnode server.']
    end

    if res['response'].include?('error_msg')
      case res['response']['error_msg']
      when 'Authentication failed!'
        return [1, 'Failed to authenticate to the Xnode server.']
      when 'Remote request-processing disabled!!'
        return [1, 'Remote request-processing is disabled on the Xnode server.']
      end
    end

    [2, 'Received unexpected response when trying to authenticate.']
  end
end
