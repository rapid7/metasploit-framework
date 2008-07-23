#---
# $Id: Header.rb,v 1.5 2006/07/30 16:54:28 bluemonk Exp $
#+++

require 'net/dns/dns'

module Net # :nodoc:
  module DNS 

    #
    # =Name
    #
    # Net::DNS::Header - DNS packet header class
    #
    # =Synopsis
    # 
    #   require 'net/dns/header'
    #
    # =Description
    # 
    # The Net::DNS::Header class represents the header portion of a 
    # DNS packet. An Header object is created whenever a new packet
    # is parsed or as user request.
    # 
    #   header = Net::DNS::Header.new
    #     # ;; id = 18123
    #     # ;; qr = 0       opCode: 0       aa = 0  tc = 0  rd = 1
    #     # ;; ra = 0       ad = 0  cd = 0  rcode = 0
    #     # ;; qdCount = 1  anCount = 0     nsCount = 0     arCount = 0
    #
    #   header.format
    #     #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #     #  |             18123             |
    #     #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #     #  |0|   0   |0|0|1|0|0| 0 |   0   |
    #     #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #     #  |               1               |
    #     #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #     #  |               0               |
    #     #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #     #  |               0               |
    #     #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #     #  |               0               |
    #     #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    #   # packet is an instance of Net::DNS::Packet
    #   header = packet.header
    #   puts "Answer is #{header.auth? ? '' : 'non'} authoritative"
    #
    # A lot of methods were written to keep a compatibility layer with
    # the Perl version of the library, as long as methods name which are
    # more or less the same. 
    #
    # =Error classes
    #
    # Some error classes has been defined for the Net::DNS::Header class,
    # which are listed here to keep a light and browsable main documentation.
    # We have:
    #
    # * HeaderArgumentError:  canonical argument error
    # * HeaderWrongCount:     a wrong +count+ parameter has been passed
    # * HeaderWrongRecursive: a wrong +recursive+ parameter has been passed
    # * HeaderWrongOpcode:    a not valid +opCode+ has been specified
    # * HeaderDuplicateID:    the requested ID is already in use
    #
    # =Copyright
    # 
    # Copyright (c) 2006 Marco Ceresa
    #
    # All rights reserved. This program is free software; you may redistribute 
    # it and/or modify it under the same terms as Ruby itself.
    #
    class Header
    
      #
      # =Name
      #
      # Net::DNS::Header::RCode - DNS Header RCode handling class
      #
      # =Synopsis
      #
      # It should be used internally by Net::DNS::Header class. However, it's still
      # possible to instantiate it directly.
      #
      #   require 'net/dns/header'
      #   rcode = Net::DNS::Header::RCode.new 0
      #
      # =Description
      #
      # The RCode class represents the RCode field in the Header portion of a  
      # DNS packet. This field (called Response Code) is used to get informations  
      # about the status of a DNS operation, such as a query or an update. These
      # are the values in the original Mockapetris's standard (RFC1035):
      #
      # * 0               No error condition
      # * 1               Format error - The name server was unable to interpret 
      #                   the query.
      # * 2               Server failure - The name server was
      #                   unable to process this query due to a
      #                   problem with the name server.
      # * 3               Name Error - Meaningful only for
      #                   responses from an authoritative name
      #                   server, this code signifies that the
      #                   domain name referenced in the query does
      #                   not exist.
      # * 4               Not Implemented - The name server does
      #                   not support the requested kind of query.
      # * 5               Refused - The name server refuses to
      #                   perform the specified operation for
      #                   policy reasons.  For example, a name
      #                   server may not wish to provide the
      #                   information to the particular requester,
      #                   or a name server may not wish to perform
      #                   a particular operation (e.g., zone
      #                   transfer) for particular data.
      # * 6-15            Reserved for future use.
      #
      # In the next DNS RFCs, codes 6-15 has been assigned to the following 
      # errors:
      #
      # * 6               YXDomain
      # * 7               YXRRSet
      # * 8               NXRRSet
      # * 9               NotAuth
      # * 10              NotZone
      #
      # More RCodes has to come for TSIGs and other operations.
      #
      class RCode
        
        # Constant for +rcode+ Response Code No Error
        NOERROR = 0
        # Constant for +rcode+ Response Code Format Error
        FORMAT = 1
        # Constant for +rcode+ Response Code Server Format Error
        SERVER = 2
        # Constant for +rcode+ Response Code Name Error
        NAME = 3
        # Constant for +rcode+ Response Code Not Implemented Error
        NOTIMPLEMENTED = 4
        # Constant for +rcode+ Response Code Refused Error
        REFUSED = 5


        
        RCodeType = %w[NoError FormErr ServFail NXDomain NotImp  
                      Refused YXDomain YXRRSet NXRRSet NotAuth NotZone]   
        
        RCodeErrorString = ["No errors",
          "The name server was unable to interpret the query",
          "The name server was unable to process this query due to problem with the name server",
          "Domain name referenced in the query does not exists",
          "The name server does not support the requested kind of query",
          "The name server refuses to perform the specified operation for policy reasons",
          "",
          "",
          "",
          "",
          ""]
        
        attr_reader :code, :type, :explanation

        def initialize(code)
          if (0..10).include? code
            @code         = code
            @type         = RCodeType[code]
            @explanation  = RCodeErrorString[code] 
          else
            raise HeaderArgumentError, "RCode #{code} out of range"
          end
        end
        
        def to_s
          @code.to_s
        end
      end
      
      # Constant for +opCode+ query
      QUERY   = 0
      # Constant for +opCode+ iquery
      IQUERY  = 1
      # Constant for +opCode+ status
      STATUS  = 2
      # Array with given strings
      OPARR = %w[QUERY IQUERY STATUS]

      @@id_arr = []
      
      # Reader for +id+ attribute  
      attr_reader :id
      # Reader for the operational code
      attr_reader :opCode
      # Reader for the rCode instance
      attr_reader :rCode
      # Reader for question section entries number
      attr_reader :qdCount
      # Reader for answer section entries number
      attr_reader :anCount
      # Reader for authority section entries number
      attr_reader :nsCount
      # Reader for addictional section entries number
      attr_reader :arCount
      
      # Creates a new Net::DNS::Header object with the desired values,
      # which can be specified as an Hash argument. When called without
      # arguments, defaults are used. If a data string is passed, values 
      # are taken from parsing the string.
      #
      # Examples:
      #
      #   # Create a new Net::DNS::Header object
      #   header = Net::DNS::Header.new
      #
      #   # Create a new Net::DNS::Header object passing values
      #   header = Net::DNS::Header.new(:opCode => 1, :rd => 0)
      #
      #   # Create a new Net::DNS::Header object with binary data
      #   header = Net::DNS::Header.new(data)
      #
      # Default values are:
      #
      #   :id => auto generated
      #   :qr      => 0 # Query response flag
      #   :aa      => 0 # Authoritative answer flag
      #   :tc      => 0 # Truncated packet flag
      #   :ra      => 0 # Recursiond available flag
      #   :rCode   => 0 # Response code (status of the query)
      #   :opCode  => 0 # Operational code (purpose of the query)
      #   :cd      => 0 # Checking disable flag
      #   :ad      => 0 # Only relevant in DNSSEC context
      #   :rd      => 1 # Recursion desired flag
      #   :qdCount => 1 # Number of questions in the dns packet
      #   :anCount => 0 # Number of answer RRs in the dns packet
      #   :nsCount => 0 # Number of authoritative RRs in the dns packet
      #   :arCount => 0 # Number of additional RRs in the dns packet
      #
      # See also each option for a detailed explanation of usage.
      #
      def initialize(arg = {})
        if arg.kind_of? Hash
          new_from_hash(arg)
        else
          raise HeaderArgumentError, "Wrong argument class: #{arg.class}"
        end
      end

      # Creates a new Net::DNS::Header object from binary data, which is 
      # passed as a string object as argument.
      # The configurations parameters are taken from parsing the string.
      #
      # Example:
      #
      #   # Create a new Net::DNS::Header object with binary data
      #   header = Net::DNS::Header.new(data)
      #
      #   header.auth? 
      #     #=> "true" if it comes from authoritative name server 
      #
      def self.parse(arg)
        if arg.kind_of? String
          o = allocate
          o.send(:new_from_binary, arg)
          o
        else
          raise HeaderArgumentError, "Wrong argument class: #{arg.class}"
        end
      end
      
      # Inspect method, prints out all the options and relative values.
      # 
      #   p Net::DNS::Header.new
      #     # ;; id = 18123
      #     # ;; qr = 0       opCode: 0       aa = 0  tc = 0  rd = 1
      #     # ;; ra = 0       ad = 0  cd = 0  rcode = 0
      #     # ;; qdCount = 1  anCount = 0     nsCount = 0     arCount = 0
      #
      # This method will maybe be changed in the future to a more pretty
      # way of display output.
      #
      def inspect 
        ";; id = #@id\n" +
          if false # @opCode == "UPDATE"
            #do stuff
          else
            ";; qr = #@qr\t" +
              "opCode: #{opCode_str}\t" +
              "aa = #@aa\t" +
              "tc = #@tc\t" +
              "rd = #@rd\n" +
              ";; ra = #@ra\t" +
              "ad = #@ad\t" +
              "cd = #@cd\t" +
              "rcode = #{@rCode.type}\n" +
              ";; qdCount = #@qdCount\t"+
              "anCount = #@anCount\t"+
              "nsCount = #@nsCount\t"+
              "arCount = #@arCount\n"
          end
      end
      
      # The Net::DNS::Header#format method prints out the header
      # in a special ascii representation of data, in a way 
      # similar to those often found on RFCs. 
      #   
      #   p Net::DNS::Header.new.format
      #     #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #     #  |             18123             |
      #     #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #     #  |0|   0   |0|0|1|0|0| 0 |   0   |
      #     #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #     #  |               1               |
      #     #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #     #  |               0               |
      #     #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #     #  |               0               |
      #     #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #     #  |               0               |
      #     #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #
      # This can be very usefull for didactical purpouses :)
      #
      def format 
        del = ("+-" * 16) + "+\n"
        len = del.length
        str = del + "|" + @id.to_s.center(len-3) + "|\n"
        str += del + "|" + @qr.to_s
        str += "|" + @opCode.to_s.center(7)
        str += "|" + @aa.to_s
        str += "|" + @tc.to_s
        str += "|" + @rd.to_s
        str += "|" + @ra.to_s
        str += "|" + @ad.to_s
        str += "|" + @cd.to_s.center(3)
        str += "|" + @rCode.to_s.center(7) + "|\n"
        str += del + "|" + @qdCount.to_s.center(len-3) + "|\n"
        str += del + "|" + @anCount.to_s.center(len-3) + "|\n"
        str += del + "|" + @nsCount.to_s.center(len-3) + "|\n"
        str += del + "|" + @arCount.to_s.center(len-3) + "|\n" + del
        str
      end
      
      # Returns the header data in binary format, appropriate 
      # for use in a DNS query packet.
      #
      #   hdata = header.data
      #   puts "Header is #{hdata.size} bytes"
      #
      def data
        arr = []
        arr.push(@id)
        arr.push((@qr<<7)|(@opCode<<3)|(@aa<<2)|(@tc<<1)|@rd)
        arr.push((@ra<<7)|(@ad<<5)|(@cd<<4)|@rCode.code)
        arr.push(@qdCount)
        arr.push(@anCount)
        arr.push(@nsCount)
        arr.push(@arCount)
        arr.pack("n C2 n4")
      end

      # Set the ID for the current header. Useful when
      # performing security tests.
      #
      def id=(val)
        if @@id_arr.include? val
          raise HeaderDuplicateID, "ID #{val} already used"
        end
        if (1..65535).include? val
          @id = val
          @@id_arr.push val
        else
          raise HeaderArgumentError, "ID #{val} out of range"
        end
      end
      
      # Checks whether the header is a query (+qr+ bit set to 0)
      #
      def query?
        @qr == 0
      end

      # Set the +qr+ query response flag to be either +true+ or 
      # +false+. You can also use the values 0 and 1. This flag 
      # indicates if the DNS packet contains a query or an answer,
      # so it should be set to +true+ in DNS answer packets.
      # If +qr+ is +true+, the packet is a response.
      #
      def qr=(val)
        case val
        when true
          @qr = 1
        when false
          @qr = 0
        when 0,1
          @qr = val
        else
          raise HeaderArgumentError, ":qr must be true(or 1) or false(or 0)"
        end
      end

      # Checks whether the header is a response 
      # (+qr+ bit set to 1)
      #
      def response?
        @qr == 1
      end

      # Returns a string representation of the +opCode+
      #
      #   puts "Packet is a #{header.opCode_str}"
      #     #=> Packet is a QUERY
      #
      def opCode_str
        OPARR[@opCode]
      end

      # Set the +opCode+ variable to a new value. This fields indicates
      # the type of the question present in the DNS packet; +val+ can be 
      # one of the values QUERY, IQUERY or STATUS. 
      #
      # * QUERY is the standard DNS query
      # * IQUERY is the inverse query
      # * STATUS is used to query the nameserver for its status
      #
      # Example:
      # 
      #   include Net::DNS
      #   header = Header.new
      #   header.opCode = Header::STATUS
      #
      def opCode=(val)
        if (0..2).include? val
          @opCode = val
        else
          raise HeaderWrongOpcode, "Wrong opCode value (#{val}), must be QUERY, IQUERY or STATUS"
        end
      end

      # Checks whether the response is authoritative
      #
      #   if header.auth?
      #     puts "Response is authoritative"
      #   else
      #     puts "Answer is NOT authoritative"
      #   end
      #
      def auth?
        @aa == 1
      end

      # Set the +aa+ flag (authoritative answer) to either +true+
      # or +false+. You can also use 0 or 1. 
      #
      # This flag indicates whether a DNS answer packet contains
      # authoritative data, meaning that is was generated by a 
      # nameserver authoritative for the domain of the question.
      #
      # Must only be set to +true+ in DNS answer packets.
      #
      def aa=(val)
        case val
        when true
          @aa = 1
        when false
          @aa = 0
        when 0,1
          @aa = val
        else
          raise HeaderArgumentError, ":aa must be true(or 1) or false(or 0)"
        end
      end
      
      # Checks whether the packet was truncated
      #
      #   # Sending packet using UDP
      #   if header.truncated?
      #     puts "Warning, packet has been truncated!"
      #     # Sending packet using TCP
      #   end
      #   # Do something with the answer
      #
      def truncated?
        @tc == 1
      end

      # Set the +tc+ flag (truncated packet) to either +true+ 
      # ot +false+. You can also use 0 or 1.
      #
      # The truncated flag is used in response packets to indicate
      # that the amount of data to be trasmitted exceedes the 
      # maximum allowed by the protocol in use, tipically UDP, and 
      # that the data present in the packet has been truncated. 
      # A different protocol (such has TCP) need to be used to 
      # retrieve full data.
      #
      # Must only be set in DNS answer packets.
      #
      def tc=(val)
        case val
        when true
          @tc = 1
        when false
          @tc = 0
        when 0,1
          @tc = val
        else
          raise HeaderArgumentError, ":tc must be true(or 1) or false(or 0)"
        end
      end
      
      # Checks whether the packet has a recursion bit
      # set, meaning that recursion is desired
      #
      def recursive?
        @rd == 1
      end

      # Sets the recursion desidered bit.
      # Remember that recursion query support is
      # optional.
      #
      #   header.recursive = true
      #   hdata = header.data # suitable for sending
      #
      # Consult RFC1034 and RFC1035 for a detailed explanation
      # of how recursion works.
      #
      def recursive=(val)
        case val
        when true
          @rd = 1
        when false
          @rd = 0
        when 1
          @rd = 1
        when 0
          @rd = 0
        else
          raise HeaderWrongRecursive, "Wrong value (#{val}), please specify true (1) or false (0)"
        end
      end

      # Alias for Header#recursive= to keep compatibility
      # with the Perl version.
      #
      def rd=(val)
        self.recursive = val
      end
      
      # Checks whether recursion is available.
      # This flag is usually set by nameservers to indicate
      # that they support recursive-type queries.
      #
      def r_available?
        @ra == 1
      end

      # Set the +ra+ flag (recursion available) to either +true+ or
      # +false+. You can also use 0 and 1.
      #
      # This flag must only be set in DNS answer packets.
      #
      def ra=(val)
        case val
        when true
          @ra = 1
        when false
          @ra = 0
        when 0,1
          @ra = val
        else
          raise HeaderArgumentError, ":ra must be true(or 1) or false(or 0)"
        end
      end

      # Checks whether checking is enabled or disabled.
      #
      # Checking is enabled by default.
      #
      def checking?
        @cd == 0
      end

      # Set the +cd+ flag (checking disabled) to either +true+ 
      # ot +false+. You can also use 0 or 1.
      #
      def cd=(val)
        case val
        when true
          @cd = 1
        when false
          @cd = 0
        when 0,1
          @cd = val
        else
          raise HeaderArgumentError, ":cd must be true(or 1) or false(or 0)"
        end
      end

      # Checks whether +ad+ flag has been set.
      #
      # This flag is only relevant in DNSSEC context.
      #
      def verified?
        @ad == 1
      end

      # Set the +ad+ flag  to either +true+ 
      # ot +false+. You can also use 0 or 1.
      #
      # The AD bit is only set on answers where signatures have 
      # been cryptographically verified or the server is 
      # authoritative for the data and is allowed to set the bit by policy.
      #
      def ad=(val)
        case val
        when true
          @ad = 1
        when false
          @ad = 0
        when 0,1
          @ad = val
        else
          raise HeaderArgumentError, ":ad must be true(or 1) or false(or 0)"
        end
      end
      
      # Returns an error array for the header response code, or
      # +nil+ if no error is generated.
      #
      #   error, cause = header.rCode_str
      #   puts "Error #{error} cause by: #{cause}" if error
      #     #=> Error ForErr caused by: The name server
      #     #=> was unable to interpret the query
      #
      def rCode_str
        return rCode.type, rCode.explanation
      end

      # Checks for errors in the DNS packet
      #
      #   unless header.error?
      #     puts "No errors in DNS answer packet"
      #   end
      #
      def error?
        @rCode.code > 0
      end
      
      # Set the rCode value. This should only be done in DNS 
      # answer packets.
      #
      def rCode=(val)
        @rCode = RCode.new(val)
      end
      
      # Sets the number of entries in a question section
      #
      def qdCount=(val)
        if (0..65535).include? val
          @qdCount = val
        else
          raise HeaderWrongCount, "Wrong number of count (#{val}), must be 0-65535"
        end
      end

      # Sets the number of RRs in an answer section
      #
      def anCount=(val)
        if (0..65535).include? val
          @anCount = val
        else
          raise HeaderWrongCount, "Wrong number of count (#{val}), must be 0-65535"
        end
      end

      # Sets the number of RRs in an authority section
      #
      def nsCount=(val)
        if (0..65535).include? val
          @nsCount = val
        else
          raise HeaderWrongCount, "Wrong number of count (#{val}), must be 0-65535"
        end
      end

      # Sets the number of RRs in an addictional section
      #
      def arCount=(val)
        if (0..65535).include? val
          @arCount = val
        else
          raise HeaderWrongCount, "Wrong number of count (#{val}), must be 0-65535"
        end
      end

      private
      
      def new_from_scratch
        @id = genID # generate ad unique id
        @qr = @aa = @tc = @ra = @ad = @cd = 0
        @rCode = RCode.new(0) # no error 
        @anCount = @nsCount = @arCount = 0
        @rd = @qdCount = 1
        @opCode = QUERY # standard query, default message 
      end
      
      def new_from_binary(str)
        unless str.size == Net::DNS::HFIXEDSZ
          raise HeaderArgumentError, "Header binary data has wrong size: #{str.size} bytes"
        end
        arr = str.unpack("n C2 n4")
        @id          =  arr[0]
        @qr          = (arr[1] >> 7) & 0x01
        @opCode      = (arr[1] >> 3) & 0x0F
        @aa          = (arr[1] >> 2) & 0x01
        @tc          = (arr[1] >> 1) & 0x01
        @rd          =  arr[1] & 0x1
        @ra          = (arr[2] >> 7) & 0x01
        @ad          = (arr[2] >> 5) & 0x01
        @cd          = (arr[2] >> 4) & 0x01
        @rCode       = RCode.new(arr[2] & 0xf)
        @qdCount     =  arr[3]
        @anCount     =  arr[4]
        @nsCount     =  arr[5]
        @arCount     =  arr[6]
      end
        
      def new_from_hash(hash)
        new_from_scratch
        hash.each do |key,val|
          eval "self.#{key.to_s} = val"
        end
      end
        
      def genID
        while (@@id_arr.include?(q = rand(65535)))
        end
        @@id_arr.push(q)
        q
      end

    end # class Header

  end # class DNS
end # module Net


class HeaderArgumentError < ArgumentError # :nodoc: all
end

class HeaderWrongCount < ArgumentError # :nodoc: all
end

class HeaderWrongRecursive < ArgumentError # :nodoc: all
end

class HeaderWrongOpcode < ArgumentError # :nodoc: all
end

class HeaderDuplicateID < ArgumentError # :nodoc: all
end
