require "digest/sha1"

module Authlogic
  module CryptoProviders
    # This class was made for the users transitioning from restful_authentication. I highly discourage using this
    # crypto provider as it inferior to your other options. Please use any other provider offered by Authlogic.
    class Sha1
      class << self
        def join_token
          @join_token ||= "--"
        end
        attr_writer :join_token
        
        # The number of times to loop through the encryption. This is ten because that is what restful_authentication defaults to.
        def stretches
          @stretches ||= 10
        end
        attr_writer :stretches
        
        # Turns your raw password into a Sha1 hash.
        def encrypt(*tokens)
          tokens = tokens.flatten
          digest = tokens.shift
          stretches.times { digest = Digest::SHA1.hexdigest([digest, *tokens].join(join_token)) }
          digest
        end
        
        # Does the crypted password match the tokens? Uses the same tokens that were used to encrypt.
        def matches?(crypted, *tokens)
          encrypt(*tokens) == crypted
        end
      end
    end
  end
end