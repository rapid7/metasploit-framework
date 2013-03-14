require "digest/md5"
 
module Authlogic
  module CryptoProviders
    # This class was made for the users transitioning from md5 based systems. 
    # I highly discourage using this crypto provider as it superbly inferior 
    # to your other options.
    #
    # Please use any other provider offered by Authlogic.
    class MD5
      class << self
        attr_accessor :join_token
        
        # The number of times to loop through the encryption.
        def stretches
          @stretches ||= 1
        end
        attr_writer :stretches
        
        # Turns your raw password into a MD5 hash.
        def encrypt(*tokens)
          digest = tokens.flatten.join(join_token)
          stretches.times { digest = Digest::MD5.hexdigest(digest) }
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