# -*- coding: binary -*-
module Msf::HTTP::JBoss::Base
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
      elsif res.code < 200 || res.code >= 300
        msg = "http request failed to #{uri} [#{res.code}]"
      elsif res.code == 200
        vprint_status("Successfully called '#{uri}'")
        return res
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

  def http_verb
    datastore['VERB']
  end

end
