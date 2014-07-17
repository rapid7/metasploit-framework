# -*- coding: binary -*-
module Msf::HTTP::JBoss::URI
  def call_uri_mtimes(uri, num_attempts = 5, verb = nil, data = nil)
    verb = datastore['VERB'] if verb.nil?

    # JBoss might need some time for the deployment. Try 5 times at most and
    # wait 5 seconds inbetween tries
    num_attempts.times do |attempt|

      if (verb == "POST")
        res = send_request_cgi(
          {
            'uri'    => uri,
            'method' => verb,
            'data'   => data
          }, 5)
      else

        uri += "?#{data}" unless data.nil?
        res = send_request_cgi(
          {
            'uri'    => uri,
            'method' => verb
          }, 30)
      end

      msg = nil
      if (!res)
        msg = "Execution failed on #{uri} [No Response]"
      elsif (res.code < 200 or res.code >= 300)
        msg = "http request failed to #{uri} [#{res.code}]"
      elsif (res.code == 200)
        print_status("Successfully called '#{uri}'") if datastore['VERBOSE']
        return res
      end

      if (attempt < num_attempts - 1)
        msg << ", retrying in 5 seconds..."
        print_status(msg) if datastore['VERBOSE']
        select(nil, nil, nil, 5)
      else
        print_error(msg)
        return res
      end
    end
  end
end
