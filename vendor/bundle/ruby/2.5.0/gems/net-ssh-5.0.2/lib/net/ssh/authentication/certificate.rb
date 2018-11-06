require 'securerandom'

module Net
  module SSH
    module Authentication
      # Class for representing an SSH certificate.
      #
      # http://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.bin/ssh/PROTOCOL.certkeys?rev=1.10&content-type=text/plain
      class Certificate
        attr_accessor :nonce
        attr_accessor :key
        attr_accessor :serial
        attr_accessor :type
        attr_accessor :key_id
        attr_accessor :valid_principals
        attr_accessor :valid_after
        attr_accessor :valid_before
        attr_accessor :critical_options
        attr_accessor :extensions
        attr_accessor :reserved
        attr_accessor :signature_key
        attr_accessor :signature

        # Read a certificate blob associated with a key of the given type.
        def self.read_certblob(buffer, type)
          cert = Certificate.new
          cert.nonce = buffer.read_string
          cert.key = buffer.read_keyblob(type)
          cert.serial = buffer.read_int64
          cert.type = type_symbol(buffer.read_long)
          cert.key_id = buffer.read_string
          cert.valid_principals = buffer.read_buffer.read_all(&:read_string)
          cert.valid_after = Time.at(buffer.read_int64)
          cert.valid_before = Time.at(buffer.read_int64)
          cert.critical_options = read_options(buffer)
          cert.extensions = read_options(buffer)
          cert.reserved = buffer.read_string
          cert.signature_key = buffer.read_buffer.read_key
          cert.signature = buffer.read_string
          cert
        end

        def ssh_type
          key.ssh_type + "-cert-v01@openssh.com"
        end

        def ssh_signature_type
          key.ssh_type
        end

        # Serializes the certificate (and key).
        def to_blob
          Buffer.from(
            :raw, to_blob_without_signature,
            :string, signature
          ).to_s
        end

        def ssh_do_sign(data)
          key.ssh_do_sign(data)
        end

        def ssh_do_verify(sig, data)
          key.ssh_do_verify(sig, data)
        end

        def to_pem
          key.to_pem
        end

        def fingerprint
          key.fingerprint
        end

        # Signs the certificate with key.
        def sign!(key, sign_nonce=nil)
          # ssh-keygen uses 32 bytes of nonce.
          self.nonce = sign_nonce || SecureRandom.random_bytes(32)
          self.signature_key = key
          self.signature = Net::SSH::Buffer.from(
            :string, key.ssh_signature_type,
            :mstring, key.ssh_do_sign(to_blob_without_signature)
          ).to_s
          self
        end

        def sign(key, sign_nonce=nil)
          cert = clone
          cert.sign!(key, sign_nonce)
        end

        # Checks whether the certificate's signature was signed by signature key.
        def signature_valid?
          buffer = Buffer.new(signature)
          buffer.read_string # skip signature format
          signature_key.ssh_do_verify(buffer.read_string, to_blob_without_signature)
        end

        def self.read_options(buffer)
          names = []
          options = buffer.read_buffer.read_all do |b|
            name = b.read_string
            names << name
            data = b.read_string
            data = Buffer.new(data).read_string unless data.empty?
            [name, data]
          end

          raise ArgumentError, "option/extension names must be in sorted order" if names.sort != names

          Hash[options]
        end
        private_class_method :read_options

        def self.type_symbol(type)
          types = { 1 => :user, 2 => :host }
          raise ArgumentError("unsupported type: #{type}") unless types.include?(type)
          types.fetch(type)
        end
        private_class_method :type_symbol

        private

        def type_value(type)
          types = { user: 1, host: 2 }
          raise ArgumentError("unsupported type: #{type}") unless types.include?(type)
          types.fetch(type)
        end

        def ssh_time(t)
          # Times in certificates are represented as a uint64.
          [[t.to_i, 0].max, 2 << 64 - 1].min
        end

        def to_blob_without_signature
          Buffer.from(
            :string, ssh_type,
            :string, nonce,
            :raw, key_without_type,
            :int64, serial,
            :long, type_value(type),
            :string, key_id,
            :string, valid_principals.inject(Buffer.new) { |acc, elem| acc.write_string(elem) }.to_s,
            :int64, ssh_time(valid_after),
            :int64, ssh_time(valid_before),
            :string, options_to_blob(critical_options),
            :string, options_to_blob(extensions),
            :string, reserved,
            :string, signature_key.to_blob
          ).to_s
        end

        def key_without_type
          # key.to_blob gives us e.g. "ssh-rsa,<key>" but we just want "<key>".
          tmp = Buffer.new(key.to_blob)
          tmp.read_string # skip the underlying key type
          tmp.read
        end

        def options_to_blob(options)
          options.keys.sort.inject(Buffer.new) do |b, name|
            b.write_string(name)
            data = options.fetch(name)
            data = Buffer.from(:string, data).to_s unless data.empty?
            b.write_string(data)
          end.to_s
        end
      end
    end
  end
end
