module Rex
  module Proto
    module Kerberos
      module Crypto
        module Asn1Utils
          # Some crypto schemes just decide to add a bunch of null bytes as padding,  and 
          # leave it up to the application to decide how many of those null bytes to remove.
          # We can't just remove all zeroes from the end of the data, because some of them
          # may actually be part of the data. The assumption here is that the information
          # about how many bytes to use comes from the ASN1 data structure. So here we ask
          # the ASN1 parser's enclosing (first) element "How many bytes do you take up?"
          def truncate_nulls_after_asn1(input)
             valid_until = 0
             OpenSSL::ASN1.traverse(input) do | depth, offset, header_len, length, constructed, tag_class, tag|
               valid_until = offset + length + header_len
               break
             end
             
             # For this to be a valid result, we expect this byte, and all following it, to be zeroes. Alternatively, there could be no padding at all (e.g. block multiple)
             suffix = input[valid_until, input.length]
             expected_result = suffix == "" || suffix.unpack('C*').all? {|char| char == 0}
             raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to truncate decrypted data' unless expected_result

             return input[0,valid_until]
          end
        end
      end
    end
  end
end

