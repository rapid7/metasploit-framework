module Metasploit
  module Framework
    module Version
      MAJOR = 4
      MINOR = 10
      PATCH = 1
      PRERELEASE = 'dev'
    end

    VERSION = "#{Version::MAJOR}.#{Version::MINOR}.#{Version::PATCH}-#{Version::PRERELEASE}"
    GEM_VERSION = VERSION.gsub('-', '.pre.')
  end
end
