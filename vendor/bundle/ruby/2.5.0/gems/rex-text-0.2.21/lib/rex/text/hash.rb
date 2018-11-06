# -*- coding: binary -*-
module Rex
  module Text
    # We are re-opening the module to add these module methods.
    # Breaking them up this way allows us to maintain a little higher
    # degree of organisation and make it easier to find what you're looking for
    # without hanging the underlying calls that we historically rely upon.

    #
    # Raw MD5 digest of the supplied string
    #
    def self.md5_raw(str)
      Digest::MD5.digest(str)
    end

    #
    # Hexidecimal MD5 digest of the supplied string
    #
    def self.md5(str)
      Digest::MD5.hexdigest(str)
    end

    #
    # Raw SHA1 digest of the supplied string
    #
    def self.sha1_raw(str)
      Digest::SHA1.digest(str)
    end

    #
    # Hexidecimal SHA1 digest of the supplied string
    #
    def self.sha1(str)
      Digest::SHA1.hexdigest(str)
    end
    
    #
    # Raw SHA2 digest of the supplied string
    #
    def self.sha2_raw(str)
      Digest::SHA2.digest(str)
    end

    #
    # Hexidecimal SHA2 digest of the supplied string
    #
    def self.sha2(str)
      Digest::SHA2.hexdigest(str)
    end
  end
end
