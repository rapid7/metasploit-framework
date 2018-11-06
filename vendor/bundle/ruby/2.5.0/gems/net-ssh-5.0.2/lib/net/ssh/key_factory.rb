require 'net/ssh/transport/openssl'
require 'net/ssh/prompt'

require 'net/ssh/authentication/ed25519_loader'

module Net
  module SSH

    # A factory class for returning new Key classes. It is used for obtaining
    # OpenSSL key instances via their SSH names, and for loading both public and
    # private keys. It used used primarily by Net::SSH itself, internally, and
    # will rarely (if ever) be directly used by consumers of the library.
    #
    #   klass = Net::SSH::KeyFactory.get("rsa")
    #   assert klass.is_a?(OpenSSL::PKey::RSA)
    #
    #   key = Net::SSH::KeyFactory.load_public_key("~/.ssh/id_dsa.pub")
    class KeyFactory
      # Specifies the mapping of SSH names to OpenSSL key classes.
      MAP = {
        "dh"  => OpenSSL::PKey::DH,
        "rsa" => OpenSSL::PKey::RSA,
        "dsa" => OpenSSL::PKey::DSA
      }
      if defined?(OpenSSL::PKey::EC)
        MAP["ecdsa"] = OpenSSL::PKey::EC
        MAP["ed25519"] = Net::SSH::Authentication::ED25519::PrivKey if defined? Net::SSH::Authentication::ED25519
      end

      class <<self
        # Fetch an OpenSSL key instance by its SSH name. It will be a new,
        # empty key of the given type.
        def get(name)
          MAP.fetch(name).new
        end

        # Loads a private key from a file. It will correctly determine
        # whether the file describes an RSA or DSA key, and will load it
        # appropriately. The new key is returned. If the key itself is
        # encrypted (requiring a passphrase to use), the user will be
        # prompted to enter their password unless passphrase works.
        def load_private_key(filename, passphrase=nil, ask_passphrase=true, prompt=Prompt.default)
          data = File.read(File.expand_path(filename))
          load_data_private_key(data, passphrase, ask_passphrase, filename, prompt)
        end

        # Loads a private key. It will correctly determine
        # whether the file describes an RSA or DSA key, and will load it
        # appropriately. The new key is returned. If the key itself is
        # encrypted (requiring a passphrase to use), the user will be
        # prompted to enter their password unless passphrase works.
        def load_data_private_key(data, passphrase=nil, ask_passphrase=true, filename="", prompt=Prompt.default)
          key_read, error_classes = classify_key(data, filename)

          encrypted_key = data.match(/ENCRYPTED/)
          tries = 0

          prompter = nil
          result =
            begin
              key_read[data, passphrase || 'invalid']
            rescue *error_classes
              if encrypted_key && ask_passphrase
                tries += 1
                if tries <= 3
                  prompter ||= prompt.start(type: 'private_key', filename: filename, sha: Digest::SHA256.digest(data))
                  passphrase = prompter.ask("Enter passphrase for #{filename}:", false)
                  retry
                else
                  raise
                end
              else
                raise
              end
            end
          prompter.success if prompter
          result
        end

        # Loads a public key from a file. It will correctly determine whether
        # the file describes an RSA or DSA key, and will load it
        # appropriately. The new public key is returned.
        def load_public_key(filename)
          data = File.read(File.expand_path(filename))
          load_data_public_key(data, filename)
        end

        # Loads a public key. It will correctly determine whether
        # the file describes an RSA or DSA key, and will load it
        # appropriately. The new public key is returned.
        def load_data_public_key(data, filename="")
          fields = data.split(/ /)

          blob = nil
          begin
            blob = fields.shift
          end while !blob.nil? && !/^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp\d+)(-cert-v01@openssh\.com)?$/.match(blob)
          blob = fields.shift

          raise Net::SSH::Exception, "public key at #{filename} is not valid" if blob.nil?

          blob = blob.unpack("m*").first
          reader = Net::SSH::Buffer.new(blob)
          reader.read_key or raise OpenSSL::PKey::PKeyError, "not a public key #{filename.inspect}"
        end

        private

        # Determine whether the file describes an RSA or DSA key, and return how load it
        # appropriately.
        def classify_key(data, filename)
          if data.match(/-----BEGIN OPENSSH PRIVATE KEY-----/)
            Net::SSH::Authentication::ED25519Loader.raiseUnlessLoaded("OpenSSH keys only supported if ED25519 is available")
            return ->(key_data, passphrase) { Net::SSH::Authentication::ED25519::PrivKey.read(key_data, passphrase) }, [ArgumentError]
          elsif OpenSSL::PKey.respond_to?(:read)
            return ->(key_data, passphrase) { OpenSSL::PKey.read(key_data, passphrase) }, [ArgumentError, OpenSSL::PKey::PKeyError]
          elsif data.match(/-----BEGIN DSA PRIVATE KEY-----/)
            return ->(key_data, passphrase) { OpenSSL::PKey::DSA.new(key_data, passphrase) }, [OpenSSL::PKey::DSAError]
          elsif data.match(/-----BEGIN RSA PRIVATE KEY-----/)
            return ->(key_data, passphrase) { OpenSSL::PKey::RSA.new(key_data, passphrase) }, [OpenSSL::PKey::RSAError]
          elsif data.match(/-----BEGIN EC PRIVATE KEY-----/) && defined?(OpenSSL::PKey::EC)
            return ->(key_data, passphrase) { OpenSSL::PKey::EC.new(key_data, passphrase) }, [OpenSSL::PKey::ECError]
          elsif data.match(/-----BEGIN (.+) PRIVATE KEY-----/)
            raise OpenSSL::PKey::PKeyError, "not a supported key type '#{$1}'"
          else
            raise OpenSSL::PKey::PKeyError, "not a private key (#{filename})"
          end
        end
      end
    end
  end
end
