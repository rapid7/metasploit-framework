module Rex
  module Parser
    # @author Kali-Team
    module Dbeaver

      module Error
        class DbeaverError < StandardError
        end

        class ParserError < DbeaverError
        end

        class DecryptionError < ParserError
        end
      end

      SECRET_KEY = 'sdf@!#$verf^wv%6Fwe%$$#FFGwfsdefwfe135s$^H)dg'.freeze
      AES_KEY = "\xBA\xBBJ\x9FwJ\xB8S\xC9l-e=\xFETJ".freeze
      # decrypt_dbeaver_credentials
      #
      # @param credentials_config_data [String]
      # @return [String] plaintext
      def decrypt_dbeaver_credentials(credentials_config_data)
        aes = OpenSSL::Cipher.new('AES-128-CBC')
        begin
          aes.decrypt
          aes.key = AES_KEY
          plaintext = aes.update(credentials_config_data)
          plaintext << aes.final
        rescue OpenSSL::Cipher::CipherError => e
          raise Error::DecryptionError, 'Unable to decrypt dbeaver credentials'
        end
        return plaintext[plaintext.index('{"')..]
      end

      # parse_credentials
      #
      # @param credentials_config_data [String]
      # @return [Hash] result_hashmap
      def parse_credentials(credentials_config_data)
        decrypt_data = decrypt_dbeaver_credentials(credentials_config_data)
        result_hashmap = Hash.new
        begin
          result_hashmap = JSON.parse(decrypt_data)
        rescue ::JSON::ParserError => e
          raise Error::ParserError, "[parse_credentials] #{e.class} - #{e}"
        end
        return result_hashmap
      end

      # parse_data_sources
      #
      # @param data_sources_data [String]
      # @param credentials_config_data [String]
      # @return [Hash] result_hashmap
      def parse_data_sources(data_sources_data, credentials_config_data)
        credentials = parse_credentials(credentials_config_data)
        result_hashmap = Hash.new
        if credentials.empty?
          return result_hashmap
        end

        begin
          data_sources = JSON.parse(data_sources_data)
          connections = data_sources['connections']
          if connections.nil? || connections.empty?
            return result_hashmap
          end

          connections.each do |data_source_id, item|
            next if item['configuration'].nil?

            result_hashmap[data_source_id] = Hash[
              'name' => item['name'] || '',
              'provider' => item['provider'] || '',
              'host' => item['configuration']['host'] || '',
              'port' => item['configuration']['port'] || '',
              'user' => credentials.key?(data_source_id) ? credentials[data_source_id]['#connection']['user'] : '',
              'password' => credentials.key?(data_source_id) ? credentials[data_source_id]['#connection']['password'] : '',
              'database' => item['configuration']['database'] || '',
              'url' => item['configuration']['url'] || '',
              'type' => item['configuration']['type'] || ''
          ]
          end
        rescue ::JSON::ParserError => e
          raise Error::ParserError, "[parse_data_sources] #{e.class} - #{e}"
        end
        return result_hashmap
      end

      # decrypt_dbeaver_6_1_3
      #
      # @param base64_string [String]
      # @return [String]
      def decrypt_dbeaver_6_1_3(base64_string)
        plaintext = ''
        if base64_string.nil?
          return plaintext
        end

        data = Rex::Text.decode_base64(base64_string)
        for i in 0..data.length - 3
          xor_data = Rex::Text.xor(data[i], SECRET_KEY[i % SECRET_KEY.length])
          plaintext += xor_data
        end
        return plaintext
      end

      # parse_data_sources_xml
      #
      # @param data_sources_data [String]
      # @return [Hash] result_hashmap
      def parse_data_sources_xml(data_sources_data)
        mxml = REXML::Document.new(data_sources_data).root
        unless mxml
          raise Error::ParserError, '[parse_data_sources_xml] XML parsing error'
        end
        result_hashmap = Hash.new
        mxml.elements.to_a('//data-sources//data-source//connection//').each do |node|
          next unless node.name == 'connection'

          data_source_id = node.parent.attributes['id']
          result_hashmap[data_source_id] = Hash[
            'name' => node.parent.attributes['name'] || '',
            'provider' => node.parent.attributes['provider'] || '',
            'host' => node.attributes['host'] || '',
            'port' => node.attributes['port'] || '',
            'user' => node.attributes['user'] || '',
            'password' => decrypt_dbeaver_6_1_3(node.attributes['password']),
            'database' => node.attributes['database'] || '',
            'url' => node.attributes['url'] || '',
            'type' => node.attributes['type'] || ''
        ]
        end
        return result_hashmap
      end

    end
  end
end
