# -*- coding: binary -*-

module Msf::Exploit::Remote::HTTP::Nifi::Dbconnectionpool
  include Msf::Exploit::Remote::HttpClient

  class DBConnectionPoolError < StandardError
  end

  # Stop DB Connection Pool
  #
  # @param token [String] The bearer token from a valid login, or nil for no Authorization headers
  # @param db_con_pool [String] UUID of the DBConnectionPool
  def stop_dbconnectionpool(token, db_con_pool)
    vprint_status("Attempting to stop DB Connection Pool: #{db_con_pool}")
    body = {
      'disconnectedNodeAcknowledged' => false,
      'state' => 'DISABLED',
      'uiOnly' => true,
      'revision' => {
        'clientId' => 'x',
        'version' => 0
      }
    }
    opts = {
      'method' => 'PUT',
      'uri' => normalize_uri(target_uri.path, 'nifi-api', 'controller-services', db_con_pool, 'run-status'),
      'ctype' => 'application/json',
      'data' => body.to_json
    }
    opts['headers'] = { 'Authorization' => "Bearer #{token}" } if token
    res = send_request_cgi(opts)
    raise DBConnectionPoolError if res.nil?

    unless res.code == 200
      print_bad("Unexpected response code: #{res.code}")
      raise DBConnectionPoolError
    end
    print_good('DB Connection Pool Stop sent successfully')
  end

  # Delete DB Connection Pool
  #
  # @param token [String] The bearer token from a valid login, or nil for no Authorization headers
  # @param db_con_pool [String] UUID of the DBConnectionPool
  # @param version [Integer] version of the DBConnectionPool to delete
  def delete_dbconnectionpool(token, db_con_pool, version = 0)
    vprint_status("Attempting to delete version #{version} of DB Connection Pool: #{db_con_pool}")
    opts = {
      'method' => 'DELETE',
      'uri' => normalize_uri(target_uri.path, 'nifi-api', 'controller-services', db_con_pool),
      'vars_get' => { 'version' => version }
    }
    opts['headers'] = { 'Authorization' => "Bearer #{token}" } if token
    res = send_request_cgi(opts)

    raise DBConnectionPoolError if res.nil?

    while res.code == 400 && res.body.include?('is not the most up-to-date revision') && version <= 20
      version += 1
      opts['vars_get'] = { 'version' => version }

      res = send_request_cgi(opts)
      raise DBConnectionPoolError if res.nil?

      vprint_status("Found newer revision of #{db_con_pool}, attempting to delete version #{version}") if res.code == 400 && res.body.include?('is not the most up-to-date revision')
    end

    if version == 20
      print_bad("Aborting after attempting to delete #{version} version of DB Connection Pool: #{db_con_pool}")
      raise DBConnectionPoolError
    end

    unless res.code == 200
      print_bad("Unexpected response code: #{res.code}")
      raise DBConnectionPoolError
    end
    print_good('DB Connection Pool Delete sent successfully')
  end

  # Start DB Connection Pool
  #
  # @param token [String] The bearer token from a valid login, or nil for no Authorization headers
  # @param db_con_pool [String] UUID of the DBConnectionPool
  def start_dbconnectionpool(token, db_con_pool)
    vprint_status("Attempting to start DB Connection Pool: #{db_con_pool}")
    body = {
      'disconnectedNodeAcknowledged' => false,
      'state' => 'ENABLED',
      'uiOnly' => true,
      'revision' => {
        'clientId' => 'x',
        'version' => 0
      }
    }
    opts = {
      'method' => 'PUT',
      'uri' => normalize_uri(target_uri.path, 'nifi-api', 'controller-services', db_con_pool, 'run-status'),
      'ctype' => 'application/json',
      'data' => body.to_json
    }
    opts['headers'] = { 'Authorization' => "Bearer #{token}" } if token
    res = send_request_cgi(opts)
    raise DBConnectionPoolError if res.nil?

    unless res.code == 200
      print_bad("Unexpected response code: #{res.code}")
      raise DBConnectionPoolError
    end
    print_good('DB Connection Pool Start sent successfully')
  end

  # Create DB Connection Pool
  #
  # @param token [String] The bearer token from a valid login, or nil for no Authorization headers
  # @param name [String] Name to give to the db connection pool
  # @param process_group [String] UUID of the process_group
  # @param nifi_version [String] version number of the nifi instance

  def create_dbconnectionpool(token, name, process_group, nifi_version)
    vprint_status("Attempting to create DB Connection Pool in Process Group: #{process_group}")
    body = {
      'revision' =>
          {
            'clientId' => 'x',
            'version' => 0
          },
      'disconnectedNodeAcknowledged' => false,
      'component' => {
        'type' => 'org.apache.nifi.dbcp.DBCPConnectionPool',
        'bundle' => {
          'group' => 'org.apache.nifi',
          'artifact' => 'nifi-dbcp-service-nar',
          'version' => nifi_version.to_s
        },
        'name' => name
      }
    }
    opts = {
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'nifi-api', 'process-groups', process_group, 'controller-services'),
      'ctype' => 'application/json',
      'data' => body.to_json
    }
    opts['headers'] = { 'Authorization' => "Bearer #{token}" } if token
    res = send_request_cgi(opts)
    raise DBConnectionPoolError if res.nil?

    unless res.code == 201
      print_bad("Unexpected response code: #{res.code}")
      raise DBConnectionPoolError
    end
    print_good('DB Connection Pool Created successfully')
    res.get_json_document['id']
  end
end
