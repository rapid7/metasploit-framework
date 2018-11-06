# Canonical `Metasploit::Credential::Login#status`.
#
# `Metasploit::Credential::Login#status` is restricted to values in {ALL}, so new valid values need to be added to this
# module:
#
# 1. Add a String constant where the constant name is in SCREAMING_SNAKE_CASE and the String in Title Case.  The String
#    should work in the sentences 'Login status is <status>' and 'Login is <status>'.
# 2. Add the new constant to {ALL}.
#
# @example 'Succeeded'
#    # 1. Try 'Succeeded' in 'Login is Succeeded'
#    # 2. It does not work, so change to 'Successful': 'Login is Successful'
#    # 3. 'Successful' works in the sentence, so write the code.
#
#    # When the `Metasploit::Credential::Login#service` allows access using `Metasploit::Credential::Login#core`.
#    SUCCESSFUL = 'Successful'
#
#    # All values that are valid for `Metasploit::Credential::Login#status`.
#    ALL = [
#      # ...
#      SUCCESSFUL,
#      # ...
#    ]
module Metasploit::Model::Login::Status
  #
  # CONSTANTS
  #

  # When `Metasploit::Credential::Login#service` returns that access is denied to `Metasploit::Credential::Login#core`.
  DENIED_ACCESS = 'Denied Access'

  # When `Metasploit::Credential::Login#service` reports that `Metasploit::Credential::Login#core` are correct, but
  # the account is disabled.
  DISABLED = 'Disabled'

  # When `Metasploit::Credential::Login#service` reports that `Metasploit::Credential::Login#core` are not correct.
  INCORRECT = 'Incorrect'

  # When `Metasploit::Credential::Login#service` reports that account tied to `Metasploit::Credential::Login#core`
  # has had too many incorrect credentials attempted for authorization, so it is locked out to prevent bruteforce
  # guessing
  LOCKED_OUT = 'Locked Out'

  # This status will never be used for a Login, but is required as a result status for certain LoginScanners.
  NO_AUTH_REQUIRED = 'No Auth Required'

  # When the `Metasploit::Credential::Login#service` allows access using `Metasploit::Credential::Login#core`.
  SUCCESSFUL = 'Successful'

  # When `Metasploit::Credential::Login#service` cannot be accessed or a timeout occurs waiting for a response from
  # `Metasploit::Credential::Login#service`.
  UNABLE_TO_CONNECT = 'Unable to Connect'

  # When `Metasploit::Credential::Login#core` has not yet been submitted to `Metasploit::Credential::Login#service`.
  UNTRIED = 'Untried'

  # All values that are valid for `Metasploit::Credential::Login#status`.
  ALL = [
      DENIED_ACCESS,
      DISABLED,
      INCORRECT,
      LOCKED_OUT,
      NO_AUTH_REQUIRED,
      SUCCESSFUL,
      UNABLE_TO_CONNECT,
      UNTRIED
  ]
end