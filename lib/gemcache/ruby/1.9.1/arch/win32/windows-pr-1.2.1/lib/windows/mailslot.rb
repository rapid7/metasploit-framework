require 'windows/api'

# The Windows module serves as a namespace only.
module Windows
  # The Mailslot module contains functions and constants related to the
  # Windows mailslot IPC mechanism.
  module Mailslot
    API.auto_namespace = 'Windows::Mailslot'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private

    # Constants

    MAILSLOT_WAIT_FOREVER = 0xFFFFFFFF
    MAILSLOT_NO_MESSAGE   = 0xFFFFFFFF

    API.new('CreateMailslot', 'SLLP', 'L')
    API.new('GetMailslotInfo', 'LPPPP', 'B')
    API.new('SetMailslotInfo', 'LL', 'B')
  end
end
