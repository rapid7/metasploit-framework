# -*- coding: binary -*-

module Msf::HTTP::JBoss::Base

  # Deploys a WAR through HTTP uri invoke
  #
  # @param opts [Hash] Hash containing {Exploit::Remote::HttpClient#send_request_cgi} options
  # @param num_attempts [Integer] The number of attempts 
  # @return [Rex::Proto::Http::Response, nil] The {Rex::Proto::Http::Response} response if exists, nil otherwise
  def deploy(opts = {}, num_attempts = 5)
    uri = opts['uri']

    if uri.blank?
      return nil
    end

    # JBoss might need some time for the deployment. Try 5 times at most and
    # wait 5 seconds inbetween tries
    num_attempts.times do |attempt|
      res = send_request_cgi(opts, 5)
      msg = nil
      if res.nil?
        msg = "Execution failed on #{uri} [No Response]"
      elsif res.code == 200
        vprint_status("Successfully called '#{uri}'")
        return res
      else
        msg = "http request failed to #{uri} [#{res.code}]"
      end

      if attempt < num_attempts - 1
        msg << ", retrying in 5 seconds..."
        vprint_status(msg)
        Rex.sleep(5)
      else
        print_error(msg)
        return res
      end
    end
  end

  # Provides the HTTP verb used
  #
  # @return [String] The HTTP verb in use
  def http_verb
    datastore['VERB']
  end

end
