module Metasploit
  module Framework
    module Version
      MAJOR = 4
      MINOR = 9
      PATCH = 2
      PRERELEASE = 'dev'
    end

    VERSION = "#{Version::MAJOR}.#{Version::MINOR}.#{Version::PATCH}-#{Version::PRERELEASE}"
  end
end
