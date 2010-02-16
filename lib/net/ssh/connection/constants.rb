module Net; module SSH; module Connection

  # Definitions of constants that are specific to the connection layer of the
  # SSH protocol.
  module Constants

    #--
    # Connection protocol generic messages
    #++

    GLOBAL_REQUEST            = 80
    REQUEST_SUCCESS           = 81
    REQUEST_FAILURE           = 82

    #--
    # Channel related messages
    #++

    CHANNEL_OPEN              = 90
    CHANNEL_OPEN_CONFIRMATION = 91
    CHANNEL_OPEN_FAILURE      = 92
    CHANNEL_WINDOW_ADJUST     = 93
    CHANNEL_DATA              = 94
    CHANNEL_EXTENDED_DATA     = 95
    CHANNEL_EOF               = 96
    CHANNEL_CLOSE             = 97
    CHANNEL_REQUEST           = 98
    CHANNEL_SUCCESS           = 99
    CHANNEL_FAILURE           = 100

  end

end; end end