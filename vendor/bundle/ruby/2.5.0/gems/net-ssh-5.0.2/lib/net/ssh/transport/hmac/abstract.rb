require 'openssl'
require 'openssl/digest'

module Net
  module SSH
    module Transport
      module HMAC

        # The base class of all OpenSSL-based HMAC algorithm wrappers.
        class Abstract
          class <<self
            def key_length(*v)
              @key_length = nil if !defined?(@key_length)
              if v.empty?
                @key_length = superclass.key_length if @key_length.nil? && superclass.respond_to?(:key_length)
                return @key_length
              elsif v.length == 1
                @key_length = v.first
              else
                raise ArgumentError, "wrong number of arguments (#{v.length} for 1)"
              end
            end

            def mac_length(*v)
              @mac_length = nil if !defined?(@mac_length)
              if v.empty?
                @mac_length = superclass.mac_length if @mac_length.nil? && superclass.respond_to?(:mac_length)
                return @mac_length
              elsif v.length == 1
                @mac_length = v.first
              else
                raise ArgumentError, "wrong number of arguments (#{v.length} for 1)"
              end
            end

            def digest_class(*v)
              @digest_class = nil if !defined?(@digest_class)
              if v.empty?
                @digest_class = superclass.digest_class if @digest_class.nil? && superclass.respond_to?(:digest_class)
                return @digest_class
              elsif v.length == 1
                @digest_class = v.first
              else
                raise ArgumentError, "wrong number of arguments (#{v.length} for 1)"
              end
            end
          end

          def key_length
            self.class.key_length
          end

          def mac_length
            self.class.mac_length
          end

          def digest_class
            self.class.digest_class
          end

          # The key in use for this instance.
          attr_reader :key

          def initialize(key=nil)
            self.key = key
          end

          # Sets the key to the given value, truncating it so that it is the correct
          # length.
          def key=(value)
            @key = value ? value.to_s[0,key_length] : nil
          end

          # Compute the HMAC digest for the given data string.
          def digest(data)
            OpenSSL::HMAC.digest(digest_class.new, key, data)[0,mac_length]
          end
        end
      end
    end
  end
end
