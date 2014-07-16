module Metasploit
  module Framework
    module Version
      MAJOR = 4
      MINOR = 9
      PATCH = 3
      PRERELEASE = 'dev'
    end

    VERSION = "#{Version::MAJOR}.#{Version::MINOR}.#{Version::PATCH}-#{Version::PRERELEASE}"
    GEM_VERSION = "#{Version::MAJOR}.#{Version::MINOR}.#{Version::PATCH}.#{Version::PRERELEASE.gsub(/[^0-9a-zA-Z]/, '')}"
  end
end
