# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++
module Dnsruby
  class RR
    # Class for DNS Certificate (CERT) resource records. (see RFC 2538)
    # 
    # RFC 2782
    class CERT < RR
      ClassValue = nil #:nodoc: all
      TypeValue = Types::CERT #:nodoc: all

      # Returns the format code for the certificate
      attr_accessor :certtype
      # Returns the key tag for the public key in the certificate
      attr_accessor :keytag
      # Returns the algorithm used by the certificate
      attr_accessor :alg
      # Returns the data comprising the certificate itself (in raw binary form)
      attr_accessor :cert

      class CertificateTypes < CodeMapper
        PKIX = 1 # PKIX (X.509v3)
        SPKI = 2 # Simple Public Key Infrastructure
        PGP = 3 # Pretty Good Privacy
        IPKIX = 4 # URL of an X.509 data object
        ISPKI = 5 # URL of an SPKI certificate
        IPGP = 6 # Fingerprint and URL of an OpenPGP packet
        ACPKIX = 7 # Attribute Certificate
        IACPKIX = 8 # URL of an Attribute Certificate
        URI = 253 # Certificate format defined by URI
        OID = 254 # Certificate format defined by OID

        update()
      end

      def from_data(data) #:nodoc: all
        @certtype = CertificateTypes::new(data[0])
        @keytag = data[1]
        @alg = Dnsruby::Algorithms.new(data[2])
        @cert= data[3]
      end

      def from_hash(hash) #:nodoc: all
        @certtype = CertificateTypes::new(hash[:certtype])
        @keytag = hash[:keytag]
        @alg = Dnsruby::Algorithms.new(hash[:alg])
        @cert= hash[:cert]
      end

      def from_string(input) #:nodoc: all
        if (input != "")
          names = input.split(" ")
          begin
            @certtype = CertificateTypes::new(names[0])
          rescue ArgumentError
            @certtype = CertificateTypes::new(names[0].to_i)
          end
          @keytag = names[1].to_i
          begin
            @alg = Dnsruby::Algorithms.new(names[2])
          rescue ArgumentError
            @alg = Dnsruby::Algorithms.new(names[2].to_i)
          end
          buf = ""
          (names.length - 3).times {|index|
            buf += names[index + 3]
          }


          buf.gsub!(/\n/, "")
          buf.gsub!(/ /, "")
          @cert = buf.unpack("m*").first
        end
      end

      def rdata_to_string #:nodoc: all
        return "#{@certtype.string} #{@keytag} #{@alg.string} #{[@cert.to_s].pack("m*").gsub("\n", "")}"
      end

      def encode_rdata(msg, canonical=false) #:nodoc: all
        msg.put_pack('nnc', @certtype.code, @keytag, @alg.code)
        msg.put_bytes(@cert)
      end

      def self.decode_rdata(msg) #:nodoc: all
        certtype, keytag, alg = msg.get_unpack('nnc')
        cert = msg.get_bytes
        return self.new([certtype, keytag, alg, cert])
      end
    end
  end
end
