module Net 
  module SSH 
    module Authentication

      # Loads ED25519 support which requires optinal dependecies like
      # rbnacl, bcrypt_pbkdf
      module ED25519Loader
      
        begin
          require 'net/ssh/authentication/ed25519'
          LOADED = true
          ERROR = nil
        rescue LoadError => e
          ERROR = e
          LOADED = false
        end
      
        def self.raiseUnlessLoaded(message)
          description = ERROR.is_a?(LoadError) ? dependenciesRequiredForED25519 : ''
          description << "#{ERROR.class} : \"#{ERROR.message}\"\n" if ERROR
          raise NotImplementedError, "#{message}\n#{description}" unless LOADED
        end
      
        def self.dependenciesRequiredForED25519
          result = "net-ssh requires the following gems for ed25519 support:\n"
          result << " * ed25519 (>= 1.2, < 2.0)\n"
          result << " * bcrypt_pbkdf (>= 1.0, < 2.0)\n" unless RUBY_PLATFORM == "java"
          result << "See https://github.com/net-ssh/net-ssh/issues/565 for more information\n"
        end
      
      end
    end
  end
end
