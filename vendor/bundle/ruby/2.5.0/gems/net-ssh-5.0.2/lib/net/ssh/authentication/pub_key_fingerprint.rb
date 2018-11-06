
require 'openssl'

module Net
  module SSH
    module Authentication
      # Public key fingerprinting utility module - internal not part of API.
      # This is included in pubkey classes and called from there. All RSA, DSA, and ECC keys
      # are supported.
      #
      #     require 'net/ssh'
      #     my_pubkey_text = File.read('/path/to/id_ed25519.pub')
      #        #=> "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDB2NBh4GJPPUN1kXPMu8b633Xcv55WoKC3OkBjFAbzJ alice@example.com"
      #     my_pubkey = Net::SSH::KeyFactory.load_data_public_key(my_pubkey_text)
      #        #=> #<Net::SSH::Authentication::ED25519::PubKey:0x00007fc8e91819b0
      #     my_pubkey.fingerprint
      #        #=> "2f:7f:97:21:76:a4:0f:38:c4:fe:d8:b4:6a:39:72:30"
      #     my_pubkey.fingerprint('SHA256')
      #        #=> "SHA256:u6mXnY8P1b0FODGp8mckqOB33u8+jvkSCtJbD5Q9klg"
      module PubKeyFingerprint # :nodoc:
        # Return the key's fingerprint.  Algorithm may be either +MD5+ (default),
        # or +SHA256+. For +SHA256+, fingerprints are in the same format
        # returned by OpenSSH's <tt>`ssh-add -l -E SHA256`</tt>, i.e.,
        # trailing base64 padding '=' characters are stripped and the
        # literal string +SHA256:+ is prepended.
        def fingerprint(algorithm='MD5')
          @fingerprint ||= {}
          @fingerprint[algorithm] ||= PubKeyFingerprint.fingerprint(to_blob, algorithm)
        end

        def self.fingerprint(blob, algorithm='MD5')
          case algorithm.to_s.upcase
          when 'MD5'
            OpenSSL::Digest.hexdigest(algorithm, blob).scan(/../).join(":")
          when 'SHA256'
            "SHA256:#{Base64.encode64(OpenSSL::Digest.digest(algorithm, blob)).chomp.gsub(/=+\z/, '')}"
          else
            raise OpenSSL::Digest::DigestError, "unsupported ssh key digest #{algorithm}"
          end
        end
      end
    end
  end
end
