# Constants indicating the reason for an unsuccessful module attempt
module Msf::Module::Failure
  # The exploit settings were incorrect
  BadConfig       = 'bad-config'

  # The network service disconnected us mid-attempt
  Disconnected    = 'disconnected'

  # The application replied indication we do not have access
  NoAccess        = 'no-access'

  # No confidence in success or failure
  None            = 'none'

  # The target is not compatible with this exploit or settings
  NoTarget        = 'no-target'

  # The application endpoint or specific service was not found
  NotFound        = 'not-found'

  # The application response indicated it was not vulnerable
  NotVulnerable   = 'not-vulnerable'

  # The payload was delivered but no session was opened (AV, network, etc)
  PayloadFailed   = 'payload-failed'

  # The exploit triggered some form of timeout
  TimeoutExpired  = 'timeout-expired'

  # The application replied in an unexpected fashion
  UnexpectedReply = 'unexpected-reply'

  # No confidence in success or failure
  Unknown         = 'unknown'

  # The network service was unreachable (connection refused, etc)
  Unreachable     = 'unreachable'

  # The exploit was interrupted by the user
  UserInterrupt   = 'user-interrupt'
end