module Metasploit
  module Framework
    module API
      # @note This is a lie.  The API version is not semantically version and it's version has actually never changed
      #    even though API changes have occurred.  DO NOT base compatibility on this version.
      module Version
        MAJOR = 1
        MINOR = 0
        PATCH = 0
      end

      VERSION = "#{Version::MAJOR}.#{Version::MINOR}.#{Version::PATCH}"
      GEM_VERSION = Rex::Version.new(VERSION)
    end
  end
end
