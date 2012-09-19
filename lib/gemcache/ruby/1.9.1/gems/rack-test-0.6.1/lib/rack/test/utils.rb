module Rack
  module Test

    module Utils # :nodoc:
      include Rack::Utils

      def build_nested_query(value, prefix = nil)
        case value
        when Array
          value.map do |v|
            unless unescape(prefix) =~ /\[\]$/
              prefix = "#{prefix}[]"
            end
            build_nested_query(v, "#{prefix}")
          end.join("&")
        when Hash
          value.map do |k, v|
            build_nested_query(v, prefix ? "#{prefix}[#{escape(k)}]" : escape(k))
          end.join("&")
        when NilClass
          prefix.to_s
        else
          "#{prefix}=#{escape(value)}"
        end
      end

      module_function :build_nested_query

      def build_multipart(params, first = true)
        if first
          unless params.is_a?(Hash)
            raise ArgumentError, "value must be a Hash"
          end

          multipart = false
          query = lambda { |value|
            case value
            when Array
              value.each(&query)
            when Hash
              value.values.each(&query)
            when UploadedFile
              multipart = true
            end
          }
          params.values.each(&query)
          return nil unless multipart
        end

        flattened_params = Hash.new

        params.each do |key, value|
          k = first ? key.to_s : "[#{key}]"

          case value
          when Array
            value.map do |v|

              if (v.is_a?(Hash))
                build_multipart(v, false).each { |subkey, subvalue|
                  flattened_params["#{k}[]#{subkey}"] = subvalue
                }
              else
                flattened_params["#{k}[]"] = value
              end

            end
          when Hash
            build_multipart(value, false).each { |subkey, subvalue|
              flattened_params[k + subkey] = subvalue
            }
          else
            flattened_params[k] = value
          end
        end

        if first
          build_parts(flattened_params)
        else
          flattened_params
        end
      end

      module_function :build_multipart

    private
      def build_parts(parameters)
        parameters.map { |name, value|
          if value.respond_to?(:original_filename)
            build_file_part(name, value)

          elsif value.is_a?(Array) and value.all? { |v| v.respond_to?(:original_filename) }
            value.map do |v|
              build_file_part(name, v)
            end.join

          else
            primitive_part = build_primitive_part(name, value)
            Rack::Test.encoding_aware_strings? ? primitive_part.force_encoding('BINARY') : primitive_part
          end

        }.join + "--#{MULTIPART_BOUNDARY}--\r"
      end

      def build_primitive_part(parameter_name, value)
        unless value.is_a? Array
          value = [value]
        end
        value.map do |v|
<<-EOF
--#{MULTIPART_BOUNDARY}\r
Content-Disposition: form-data; name="#{parameter_name}"\r
\r
#{v}\r
EOF
        end.join
      end

      def build_file_part(parameter_name, uploaded_file)
        ::File.open(uploaded_file.path, "rb") do |physical_file|
          physical_file.set_encoding(Encoding::BINARY) if physical_file.respond_to?(:set_encoding)
<<-EOF
--#{MULTIPART_BOUNDARY}\r
Content-Disposition: form-data; name="#{parameter_name}"; filename="#{escape(uploaded_file.original_filename)}"\r
Content-Type: #{uploaded_file.content_type}\r
Content-Length: #{::File.stat(uploaded_file.path).size}\r
\r
#{physical_file.read}\r
EOF
        end
      end

    end

  end
end
