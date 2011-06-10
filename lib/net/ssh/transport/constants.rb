module Net; module SSH; module Transport
  module Constants

    #--
    # Transport layer generic messages
    #++

    DISCONNECT                = 1
    IGNORE                    = 2
    UNIMPLEMENTED             = 3
    DEBUG                     = 4
    SERVICE_REQUEST           = 5
    SERVICE_ACCEPT            = 6

    #--
    # Algorithm negotiation messages
    #++

    KEXINIT                   = 20
    NEWKEYS                   = 21

    #--
    # Key exchange method specific messages
    #++

    KEXDH_INIT                = 30
    KEXDH_REPLY               = 31

  end
end; end; end