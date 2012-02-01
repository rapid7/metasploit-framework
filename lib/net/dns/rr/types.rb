module Net # :nodoc:
  module DNS
    
    class RR
      
      #
      # This is an auxiliary class to hadle RR type field in a DNS packet. 
      #
      class Types
        
        # :nodoc:
        Types = { # :nodoc:
          'SIGZERO'   => 0,       # RFC2931 consider this a pseudo type
          'A'         => 1,       # RFC 1035, Section 3.4.1
          'NS'        => 2,       # RFC 1035, Section 3.3.11
          'MD'        => 3,       # RFC 1035, Section 3.3.4 (obsolete)
          'MF'        => 4,       # RFC 1035, Section 3.3.5 (obsolete)
          'CNAME'     => 5,       # RFC 1035, Section 3.3.1
          'SOA'       => 6,       # RFC 1035, Section 3.3.13
          'MB'        => 7,       # RFC 1035, Section 3.3.3
          'MG'        => 8,       # RFC 1035, Section 3.3.6
          'MR'        => 9,       # RFC 1035, Section 3.3.8
          'NULL'      => 10,      # RFC 1035, Section 3.3.10
          'WKS'       => 11,      # RFC 1035, Section 3.4.2 (deprecated)
          'PTR'       => 12,      # RFC 1035, Section 3.3.12
          'HINFO'     => 13,      # RFC 1035, Section 3.3.2
          'MINFO'     => 14,      # RFC 1035, Section 3.3.7
          'MX'        => 15,      # RFC 1035, Section 3.3.9
          'TXT'       => 16,      # RFC 1035, Section 3.3.14
          'RP'        => 17,      # RFC 1183, Section 2.2
          'AFSDB'     => 18,      # RFC 1183, Section 1
          'X25'       => 19,      # RFC 1183, Section 3.1
          'ISDN'      => 20,      # RFC 1183, Section 3.2
          'RT'        => 21,      # RFC 1183, Section 3.3
          'NSAP'      => 22,      # RFC 1706, Section 5
          'NSAP_PTR'  => 23,      # RFC 1348 (obsolete)
          # The following 2 RRs are impemented in Net::DNS::SEC, TODO
          'SIG'       => 24,      # RFC 2535, Section 4.1
          'KEY'       => 25,      # RFC 2535, Section 3.1
          'PX'        => 26,      # RFC 2163,
          'GPOS'      => 27,      # RFC 1712 (obsolete)
          'AAAA'      => 28,      # RFC 1886, Section 2.1
          'LOC'       => 29,      # RFC 1876
          # The following RR is impemented in Net::DNS::SEC, TODO
          'NXT'       => 30,      # RFC 2535, Section 5.2
          'EID'       => 31,      # draft-ietf-nimrod-dns-xx.txt
          'NIMLOC'    => 32,      # draft-ietf-nimrod-dns-xx.txt
          'SRV'       => 33,      # RFC 2052
          'ATMA'      => 34,      # ???
          'NAPTR'     => 35,      # RFC 2168
          'KX'        => 36,      # RFC 2230
          'CERT'      => 37,      # RFC 2538
          'DNAME'     => 39,      # RFC 2672
          'OPT'       => 41,      # RFC 2671
          # The following 4 RRs are impemented in Net::DNS::SEC TODO
          'DS'        => 43,      # draft-ietf-dnsext-delegation-signer
          'SSHFP'     => 44,      # draft-ietf-secsh-dns (No RFC # yet at time of coding)
          'RRSIG'     => 46,      # draft-ietf-dnsext-dnssec-2535typecode-change
          'NSEC'      => 47,      # draft-ietf-dnsext-dnssec-2535typecode-change
          'DNSKEY'    => 48,      # draft-ietf-dnsext-dnssec-2535typecode-change
          'UINFO'     => 100,     # non-standard
          'UID'       => 101,     # non-standard
          'GID'       => 102,     # non-standard
          'UNSPEC'    => 103,     # non-standard
          'TKEY'      => 249,     # RFC 2930
          'TSIG'      => 250,     # RFC 2931
          'IXFR'      => 251,     # RFC 1995
          'AXFR'      => 252,     # RFC 1035
          'MAILB'     => 253,     # RFC 1035 (MB, MG, MR)
          'MAILA'     => 254,     # RFC 1035 (obsolete - see MX)
          'ANY'       => 255,     # RFC 1035
        }

        # The default value when type is nil in Resource Records
        @@default = Types["A"]

        # Be able to control the default type to assign when
        # type is +nil+. Default to +A+
        def self.default=(str)
          if Types.has_key? str
            @@default = Types[str]
          else
            raise TypeArgumentError, "Unknown type #{str}"
          end
        end

        # Checks whether +type+ is a valid RR type.  
        def self.valid?(type)
          case type
          when String
            return Types.has_key?(type)
          when Fixnum
            return Types.invert.has_key?(type)
          else
            raise TypeArgumentError, "Wrong type class: #{type.class}"
          end
        end
        
        # Returns the type in string format, as "A" or "NS",
        # given the numeric value
        def self.to_str(type)
          case type
          when Fixnum
            if Types.invert.has_key? type
              return Types.invert[type]
            else
              raise TypeArgumentError, "Unknown type number #{type}"
            end
          else
            raise TypeArgumentError, "Wrong type class: #{type.class}"
          end
        end

        # Gives in output the keys from the +Types+ hash
        # in a format suited for regexps
        def self.regexp
          Types.keys.join("|")
        end

        # Creates a new object representing an RR type. Performs some
        # checks on the argument validity too. Il +type+ is +nil+, the
        # default value is +ANY+ or the one set with Types.default=
        def initialize(type)
          case type
          when String
            # type in the form "A" or "NS"
            new_from_string(type.upcase) 
          when Fixnum
            # type in numeric form
            new_from_num(type) 
          when nil
            # default type, control with Types.default=
            @str = Types.invert[@@default] 
            @num = @@default
          else
            raise TypeArgumentError, "Wrong type class: #{type.class}"
          end
        end
        
        # Returns the type in number format 
        # (default for normal use)
        def inspect
          @num
        end

        # Returns the type in string format,
        # i.d. "A" or "NS" or such a string.
        def to_s
          @str
        end

        # Returns the type in numeric format,
        # usable by the pack methods for data transfers
        def to_i
          @num.to_i
        end
        
        # Should be used only for testing purpouses
        def to_str
          @num.to_s
        end

        private
        
        # Constructor for string data type,
        # *PRIVATE* method
        def new_from_string(type)
          case type
          when /^TYPE\\d+/
            # TODO!!!
          else 
            # String with name of type
            if Types.has_key? type
              @str = type
              @num = Types[type]
            else
              raise TypeArgumentError, "Unknown type #{type}"
            end
          end
        end

        # Contructor for numeric data type
        # *PRIVATE* method
        def new_from_num(type)
          if Types.invert.has_key? type
            @num = type
            @str = Types.invert[type]
          else
            raise TypeArgumentError, "Unkown type number #{type}"
          end
        end
        
      end # class Types
    
    end # class RR
  end # module DNS
end # module Net

class TypeArgumentError < ArgumentError # :nodoc:
end
