module Dnsruby

  require 'dnsruby/code_mapper'

  class OpCode < CodeMapper
    Query = 0        # RFC 1035
    IQuery = 1        # RFC 1035
    Status = 2        # RFC 1035
    Notify = 4        # RFC 1996
    Update = 5        # RFC 2136

    update()
  end

  class RCode < CodeMapper
    NOERROR = 0       # RFC 1035
    FORMERR = 1       # RFC 1035
    SERVFAIL = 2       # RFC 1035
    NXDOMAIN = 3       # RFC 1035
    NOTIMP = 4       # RFC 1035
    REFUSED = 5       # RFC 1035
    YXDOMAIN = 6       # RFC 2136
    YXRRSET = 7       # RFC 2136
    NXRRSET = 8       # RFC 2136
    NOTAUTH = 9       # RFC 2136
    NOTZONE = 10       # RFC 2136

    #     BADVERS = 16 # an EDNS ExtendedRCode
    BADSIG = 16
    BADKEY = 17
    BADTIME = 18
    BADMODE = 19
    BADNAME = 20
    BADALG = 21

    update()
  end

  class ExtendedRCode < CodeMapper
    BADVERS = 16
    update()
  end

  class Classes < CodeMapper
    IN        = 1       # RFC 1035
    CH        = 3       # RFC 1035
    #     CHAOS        = 3       # RFC 1035
    HS        = 4       # RFC 1035
    #     HESIOD        = 4       # RFC 1035
    NONE      = 254     # RFC 2136
    ANY       = 255     # RFC 1035
    update()

    def unknown_string(arg)
      if (arg=~/^CLASS/i)
        Classes.add_pair(arg, arg.gsub('CLASS', '').to_i)
        set_string(arg)
      else
        raise ArgumentError.new("String #{arg} not a member of #{self.class}")
      end
    end

    def unknown_code(arg)
      Classes.add_pair('CLASS' + arg.to_s, arg)
      set_code(arg)
    end

    #  classesbyval and classesbyname functions are wrappers around the
    #  similarly named hashes. They are used for 'unknown' DNS RR classess
    #  (RFC3597)
    #  See typesbyval and typesbyname, these beasts have the same functionality
    def Classes.classesbyname(name) #:nodoc: all
      name.upcase!;
      if to_code(name)
        return to_code(name)
      end

      if ((name =~/^\s*CLASS(\d+)\s*$/o) == nil)
        raise ArgumentError, "classesbyval() argument is not CLASS### (#{name})"
      end

      val = $1.to_i
      if val > 0xffff
        raise ArgumentError, 'classesbyval() argument larger than ' + 0xffff
      end

      return val;
    end



    def Classes.classesbyval(val) #:nodoc: all
      if (val.class == String)
        if ((val =~ /^\s*0*([0-9]+)\s*$/) == nil)
          raise ArgumentError,  "classesbybal() argument is not numeric (#{val})" # unless  val.gsub!("^\s*0*([0-9]+)\s*$", "$1")
          #           val =~ s/^\s*0*([0-9]+)\s*$/$1/o;#
        end
        val = $1.to_i
      end

      return to_string(val) if to_string(val)

      raise ArgumentError,  'classesbyval() argument larger than ' + 0xffff if val > 0xffff;

      return "CLASS#{val}";
    end
  end

  #  The RR types explicitly supported by Dnsruby.
  # 
  #  New RR types should be added to this set
  class Types < CodeMapper
    SIGZERO   = 0       # RFC2931 consider this a pseudo type
    A         = 1       # RFC 1035, Section 3.4.1
    NS        = 2       # RFC 1035, Section 3.3.11
    MD        = 3       # RFC 1035, Section 3.3.4 (obsolete)
    MF        = 4       # RFC 1035, Section 3.3.5 (obsolete)
    CNAME     = 5       # RFC 1035, Section 3.3.1
    SOA       = 6       # RFC 1035, Section 3.3.13
    MB        = 7       # RFC 1035, Section 3.3.3
    MG        = 8       # RFC 1035, Section 3.3.6
    MR        = 9       # RFC 1035, Section 3.3.8
    NULL      = 10      # RFC 1035, Section 3.3.10
    WKS       = 11      # RFC 1035, Section 3.4.2 (deprecated)
    PTR       = 12      # RFC 1035, Section 3.3.12
    HINFO     = 13      # RFC 1035, Section 3.3.2
    MINFO     = 14      # RFC 1035, Section 3.3.7
    MX        = 15      # RFC 1035, Section 3.3.9
    TXT       = 16      # RFC 1035, Section 3.3.14
    RP        = 17      # RFC 1183, Section 2.2
    AFSDB     = 18      # RFC 1183, Section 1
    X25       = 19      # RFC 1183, Section 3.1
    ISDN      = 20      # RFC 1183, Section 3.2
    RT        = 21      # RFC 1183, Section 3.3
    NSAP      = 22      # RFC 1706, Section 5
    NSAP_PTR  = 23      # RFC 1348 (obsolete)
    SIG       = 24      # RFC 2535, Section 4.1
    KEY       = 25      # RFC 2535, Section 3.1
    PX        = 26      # RFC 2163,
    GPOS      = 27      # RFC 1712 (obsolete)
    AAAA      = 28      # RFC 1886, Section 2.1
    LOC       = 29      # RFC 1876
    NXT       = 30      # RFC 2535, Section 5.2 obsoleted by RFC3755
    EID       = 31      # draft-ietf-nimrod-dns-xx.txt
    NIMLOC    = 32      # draft-ietf-nimrod-dns-xx.txt
    SRV       = 33      # RFC 2052
    ATMA      = 34      # ???
    NAPTR     = 35      # RFC 2168
    KX        = 36      # RFC 2230
    CERT      = 37      # RFC 2538
    DNAME     = 39      # RFC 2672
    OPT       = 41      # RFC 2671
    APL       = 42      # RFC 3123
    DS        = 43      # RFC 4034
    SSHFP     = 44      # RFC 4255
    IPSECKEY  = 45      # RFC 4025
    RRSIG     = 46      # RFC 4034
    NSEC      = 47      # RFC 4034
    DNSKEY    = 48      # RFC 4034
    DHCID     = 49      # RFC 4701
    NSEC3     = 50      # RFC still pending at time of writing
    NSEC3PARAM= 51      # RFC still pending at time of writing
    TLSA      = 52      # RFC 6698
    HIP       = 55      # RFC 5205
    CDS       = 59      # RFC 7344
    CDNSKEY   = 60      # RFC 7344
    SPF       = 99      # RFC 4408
    UINFO     = 100     # non-standard
    UID       = 101     # non-standard
    GID       = 102     # non-standard
    UNSPEC    = 103     # non-standard
    TKEY      = 249     # RFC 2930
    TSIG      = 250     # RFC 2931
    IXFR      = 251     # RFC 1995
    AXFR      = 252     # RFC 1035
    MAILB     = 253     # RFC 1035 (MB, MG, MR)
    MAILA     = 254     # RFC 1035 (obsolete - see MX)
    ANY       = 255     # RFC 1035
    URI       = 256     # RFC 7553
    CAA       = 257     # RFC 6844
    DLV       = 32769   # RFC 4431 (informational)
    update()

    def unknown_string(arg) #:nodoc: all
      if (arg=~/^TYPE/i)
        Types.add_pair(arg, arg.gsub('TYPE', '').to_i)
        set_string(arg)
      else
        raise ArgumentError.new("String #{arg} not a member of #{self.class}")
      end
    end

    def unknown_code(arg) #:nodoc: all
      Types.add_pair('TYPE' + arg.to_s, arg)
      set_code(arg)
    end

    # --
    #  typesbyval and typesbyname functions are wrappers around the similarly named
    #  hashes. They are used for 'unknown' DNS RR types (RFC3597)
    #  typesbyname returns they TYPEcode as a function of the TYPE
    #  mnemonic. If the TYPE mapping is not specified the generic mnemonic
    #  TYPE### is returned.
    def Types.typesbyname(name)  #:nodoc: all
      name.upcase!

      if to_code(name)
        return to_code(name)
      end


      if ((name =~/^\s*TYPE(\d+)\s*$/o)==nil)
        raise ArgumentError, "Net::DNS::typesbyname() argument (#{name}) is not TYPE###"
      end

      val = $1.to_i
      if val > 0xffff
        raise ArgumentError, 'Net::DNS::typesbyname() argument larger than ' + 0xffff
      end

      return val;
    end


    #  typesbyval returns they TYPE mnemonic as a function of the TYPE
    #  code. If the TYPE mapping is not specified the generic mnemonic
    #  TYPE### is returned.
    def Types.typesbyval(val) #:nodoc: all
      if (!defined?val)
        raise ArgumentError,  "Net::DNS::typesbyval() argument is not defined"
      end

      if val.class == String
        #       if val.gsub!("^\s*0*(\d+)\s*$", "$1")
        if ((val =~ /^\s*0*(\d+)\s*$", "$1/o) == nil)
          raise ArgumentError,  "Net::DNS::typesbyval() argument (#{val}) is not numeric"
          #           val =~s/^\s*0*(\d+)\s*$/$1/o;
        end

        val = $1.to_i
      end


      if to_string(val)
        return to_string(val)
      end

      raise ArgumentError,  'Net::DNS::typesbyval() argument larger than ' + 0xffff if
          val > 0xffff;

      return "TYPE#{val}";
    end
  end

  class QTypes < CodeMapper
    IXFR   = 251  # incremental transfer                [RFC1995]
    AXFR   = 252  # transfer of an entire zone          [RFC1035]
    MAILB  = 253  # mailbox-related RRs (MB, MG or MR)   [RFC1035]
    MAILA  = 254  # mail agent RRs (Obsolete - see MX)   [RFC1035]
    ANY    = 255  # all records                      [RFC1035]
    update()
  end

  class MetaTypes < CodeMapper
    TKEY        = 249    # Transaction Key   [RFC2930]
    TSIG        = 250    # Transaction Signature  [RFC2845]
    OPT         = 41     # RFC 2671
  end

  #  http://www.iana.org/assignments/dns-sec-alg-numbers/
  class Algorithms < CodeMapper
    RESERVED   = 0
    RSAMD5     = 1
    DH         = 2
    DSA        = 3
    RSASHA1    = 5
    RSASHA256  = 8
    RSASHA512  = 10
    ECDSAP256SHA256 = 13
    ECDSAP384SHA384 = 14
    INDIRECT   = 252
    PRIVATEDNS = 253
    PRIVATEOID = 254
    update()
    #  Referred to as Algorithms.DSA_NSEC3_SHA1
    add_pair("DSA-NSEC3-SHA1", 6)
    #  Referred to as Algorithms.RSASHA1_NSEC3_SHA1
    add_pair("RSASHA1-NSEC3-SHA1", 7)
    #  Referred to as Algorithms.ECC_GOST
    add_pair("ECC-GOST",12)
  end

  #  http://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml
  class Nsec3HashAlgorithms < CodeMapper
    RESERVED = 0
    update()
    add_pair("SHA-1", 1)
  end

end
