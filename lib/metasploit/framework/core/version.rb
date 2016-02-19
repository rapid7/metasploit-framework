require 'metasploit/framework/version'

module Metasploit
  module Framework
    # @note This is a lie.  The core libraries are not semantically versioned.  This is currently just linked to the
    #   Metasploit::Framework::Version, which is also not semantically versioned.
    module Core
      module Version
        MAJOR = Metasploit::Framework::Version::MAJOR
        MINOR = Metasploit::Framework::Version::MINOR
        PATCH = Metasploit::Framework::Version::PATCH
        PRERELEASE = Metasploit::Framework::Version::PRERELEASE
      end

      VERSION = Metasploit::Framework::VERSION
      GEM_VERSION = Gem::Version.new(Metasploit::Framework::GEM_VERSION)
    end
  end
end
