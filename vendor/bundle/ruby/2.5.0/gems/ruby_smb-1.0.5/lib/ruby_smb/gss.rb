module RubySMB
  # module containing methods required for using the [GSS-API](http://www.rfc-editor.org/rfc/rfc2743.txt)
  # for Secure Protected Negotiation(SPNEGO) in SMB Authentication.
  module Gss
    # Cargo culted from Rex. Hacked Together ASN1 encoding that works for our GSS purposes
    # @todo Document these magic numbers
    def self.asn1encode(str = '')
      # If the high bit of the first byte is 1, it contains the number of
      # length bytes that follow
      case str.length
      when 0..0x7F
        encoded_string = [str.length].pack('C') + str
      when 0x80..0xFF
        encoded_string = [0x81, str.length].pack('CC') + str
      when 0x100..0xFFFF
        encoded_string = [0x82, str.length].pack('Cn') + str
      when  0x10000..0xffffff
        encoded_string = [0x83, str.length >> 16, str.length & 0xFFFF].pack('CCn') + str
      when  0x1000000..0xffffffff
        encoded_string = [0x84, str.length].pack('CN') + str
      else
        raise RubySMB::Error::ASN1Encoding, "Source string is too long. Size is #{str.length}"
      end
      encoded_string
    end

    # Create a GSS Security Blob of an NTLM Type 1 Message.
    # This code has been cargo culted and needs to be researched
    # and refactored into something better later.
    # @todo Refactor this into non-magical code
    def self.gss_type1(type1)
      "\x60".force_encoding('binary') + asn1encode(
        "\x06".force_encoding('binary') + asn1encode(
          "\x2b\x06\x01\x05\x05\x02".force_encoding('binary')
        ) +
          "\xa0".force_encoding('binary') + asn1encode(
            "\x30".force_encoding('binary') + asn1encode(
              "\xa0".force_encoding('binary') + asn1encode(
                "\x30".force_encoding('binary') + asn1encode(
                  "\x06".force_encoding('binary') + asn1encode(
                    "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a".force_encoding('binary')
                  )
                )
              ) +
                "\xa2".force_encoding('binary') + asn1encode(
                  "\x04".force_encoding('binary') + asn1encode(
                    type1
                  )
                )
            )
          )
      )
    end

    # Create a GSS Security Blob of an NTLM Type 2 Message.
    # This code has been cargo culted and needs to be researched
    # and refactored into something better later.
    def self.gss_type2(type2)
      blob =
        "\xa1" + asn1encode(
          "\x30" + asn1encode(
            "\xa0" + asn1encode(
              "\x0a" + asn1encode(
                "\x01"
              )
            ) +
              "\xa1" + asn1encode(
                "\x06" + asn1encode(
                  "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
                )
              ) +
              "\xa2" + asn1encode(
                "\x04" + asn1encode(
                  type2
                )
              )
          )
        )

      blob
    end

    # Create a GSS Security Blob of an NTLM Type 3 Message.
    # This code has been cargo culted and needs to be researched
    # and refactored into something better later.
    # @todo Refactor this into non-magical code
    def self.gss_type3(type3)
      gss =
        "\xa1".force_encoding('binary') + asn1encode(
          "\x30".force_encoding('binary') + asn1encode(
            "\xa2".force_encoding('binary') + asn1encode(
              "\x04".force_encoding('binary') + asn1encode(
                type3
              )
            )
          )
        )

      gss
    end
  end
end
