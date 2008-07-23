##
#
# dns.rb
#
# $id$
#
##

module Net # :nodoc:
  module DNS
    
    # Version of the library
    VERSION = "0.4"
  
    # Packet size in bytes
    PACKETSZ = 512
    
    # Size of the header 
    HFIXEDSZ = 12
    
    # Size of the question portion (type and class)
    QFIXEDSZ = 4
    
    # Size of an RR portion (type,class,lenght and ttl)
    RRFIXEDSZ = 10
    
    # Size of an int 32 bit
    INT32SZ = 4
    
    # Size of a short int
    INT16SZ = 2

    module QueryTypes
    
      SIGZERO   = 0
      A         = 1
      NS        = 2
      MD        = 3
      MF        = 4
      CNAME     = 5
      SOA       = 6
      MB        = 7
      MG        = 8
      MR        = 9
      NULL      = 10
      WKS       = 11
      PTR       = 12
      HINFO     = 13
      MINFO     = 14
      MX        = 15
      TXT       = 16
      RP        = 17
      AFSDB     = 18
      X25       = 19
      ISDN      = 20
      RT        = 21
      NSAP      = 22
      NSAPPTR   = 23
      SIG       = 24
      KEY       = 25
      PX        = 26
      GPOS      = 27
      AAAA      = 28
      LOC       = 29
      NXT       = 30
      EID       = 31
      NIMLOC    = 32
      SRV       = 33
      ATMA      = 34
      NAPTR     = 35
      KX        = 36
      CERT      = 37
      DNAME     = 39
      OPT       = 41
      DS        = 43
      SSHFP     = 44
      RRSIG     = 46
      NSEC      = 47
      DNSKEY    = 48
      UINFO     = 100
      UID       = 101
      GID       = 102
      UNSPEC    = 103
      TKEY      = 249
      TSIG      = 250
      IXFR      = 251
      AXFR      = 252
      MAILB     = 253
      MAILA     = 254
      ANY       = 255

    end
    
    module QueryClasses
    
      # Internet class
      IN        = 1
      
      # Chaos class
      CH        = 3
    
      # Hesiod class
      HS        = 4
      
      # None class
      NONE      = 254
      
      # Any class
      ANY       = 255
      
    end
    
    include QueryTypes
    include QueryClasses

  end # module DNS
end # module Net
