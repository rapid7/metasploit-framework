require 'net/ssh/transport/constants'
require 'net/ssh/transport/kex/diffie_hellman_group1_sha1'

module Net 
  module SSH 
    module Transport 
      module Kex

        # A key-exchange service implementing the "ecdh-sha2-nistp256"
        # key-exchange algorithm. (defined in RFC 5656)
        class EcdhSHA2NistP256 < DiffieHellmanGroup1SHA1
          include Loggable
          include Constants
      
          attr_reader :ecdh
      
          def digester
            OpenSSL::Digest::SHA256
          end
      
          def curve_name
            OpenSSL::PKey::EC::CurveNameAlias['nistp256']
          end
      
          def initialize(algorithms, connection, data)
            @algorithms = algorithms
            @connection = connection
      
            @digester = digester
            @data = data.dup
            @ecdh = generate_key
            @logger = @data.delete(:logger)
          end
      
          private
      
          def get_message_types
            [KEXECDH_INIT, KEXECDH_REPLY]
          end
      
          def build_signature_buffer(result)
            response = Net::SSH::Buffer.new
            response.write_string data[:client_version_string],
                                  data[:server_version_string],
                                  data[:client_algorithm_packet],
                                  data[:server_algorithm_packet],
                                  result[:key_blob],
                                  ecdh.public_key.to_bn.to_s(2),
                                  result[:server_ecdh_pubkey]
            response.write_bignum result[:shared_secret]
            response
          end
      
          def generate_key #:nodoc:
            OpenSSL::PKey::EC.new(curve_name).generate_key
          end
      
          def send_kexinit #:nodoc:
            init, reply = get_message_types
      
            # send the KEXECDH_INIT message
            ## byte     SSH_MSG_KEX_ECDH_INIT
            ## string   Q_C, client's ephemeral public key octet string
            buffer = Net::SSH::Buffer.from(:byte, init, :mstring, ecdh.public_key.to_bn.to_s(2))
            connection.send_message(buffer)
      
            # expect the following KEXECDH_REPLY message
            ## byte     SSH_MSG_KEX_ECDH_REPLY
            ## string   K_S, server's public host key
            ## string   Q_S, server's ephemeral public key octet string
            ## string   the signature on the exchange hash
            buffer = connection.next_message
            raise Net::SSH::Exception, "expected REPLY" unless buffer.type == reply
      
            result = Hash.new
            result[:key_blob] = buffer.read_string
            result[:server_key] = Net::SSH::Buffer.new(result[:key_blob]).read_key
            result[:server_ecdh_pubkey] = buffer.read_string
      
            # compute shared secret from server's public key and client's private key
            pk = OpenSSL::PKey::EC::Point.new(OpenSSL::PKey::EC.new(curve_name).group,
                                              OpenSSL::BN.new(result[:server_ecdh_pubkey], 2))
            result[:shared_secret] = OpenSSL::BN.new(ecdh.dh_compute_key(pk), 2)
      
            sig_buffer = Net::SSH::Buffer.new(buffer.read_string)
            sig_type = sig_buffer.read_string
            if sig_type != algorithms.host_key_format
              raise Net::SSH::Exception,
              "host key algorithm mismatch for signature " +
                "'#{sig_type}' != '#{algorithms.host_key_format}'"
            end
            result[:server_sig] = sig_buffer.read_string
      
            return result
          end
        end
      end
    end
  end
end
