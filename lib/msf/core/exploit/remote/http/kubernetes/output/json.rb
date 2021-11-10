# -*- coding: binary -*-

# Outputs Kubernetes API responses in JSON format
class Msf::Exploit::Remote::HTTP::Kubernetes::Output::JSON
  # Creates a new `Msf::Exploit::Remote::HTTP::Kubernetes::Output::JSON` instance
  #
  # @param [object] output The original output object with print_line/print_status/etc methods available.
  def initialize(output)
    @output = output
  end

  def print_error(*_args); end

  def print_good(*_args); end

  def print_status(*_args); end

  def print_enum_failure(_resource, error)
    if error.is_a?(Msf::Exploit::Remote::HTTP::Kubernetes::Error::ApiError) && error.res
      print_json(error.res.get_json_document)
    else
      output.print_error(error.message)
    end
  end

  def print_claims(claims)
    print_json(claims)
  end

  def print_version(version)
    print_json(version)
  end

  def print_namespaces(namespaces)
    print_json(namespaces)
  end

  def print_auth(_namespace, auth)
    print_json(auth)
  end

  def print_pods(_namespace, pods)
    print_json(pods)
  end

  def print_secrets(_namespace, pods)
    print_json(pods)
  end

  protected

  attr_reader :output

  def print_json(object)
    output.print_line(JSON.pretty_generate(object))
  end
end
