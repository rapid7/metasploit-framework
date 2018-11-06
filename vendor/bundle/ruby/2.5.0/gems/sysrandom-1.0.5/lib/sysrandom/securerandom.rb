require "sysrandom"

# Make sure SecureRandom has been loaded before we patch it
require "securerandom"

Object.send(:remove_const, :SecureRandom)
SecureRandom = Sysrandom
