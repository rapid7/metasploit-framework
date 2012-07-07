module CodeRay
  
  # A simplified interface to the gzip library +zlib+ (from the Ruby Standard Library.)
  module GZip
    
    require 'zlib'
    
    # The default zipping level. 7 zips good and fast.
    DEFAULT_GZIP_LEVEL = 7
    
    # Unzips the given string +s+.
    #
    # Example:
    #   require 'gzip_simple'
    #   print GZip.gunzip(File.read('adresses.gz'))
    def GZip.gunzip s
      Zlib::Inflate.inflate s
    end
    
    # Zips the given string +s+.
    #
    # Example:
    #   require 'gzip_simple'
    #   File.open('adresses.gz', 'w') do |file
    #     file.write GZip.gzip('Mum: 0123 456 789', 9)
    #   end
    #
    # If you provide a +level+, you can control how strong
    # the string is compressed:
    # - 0: no compression, only convert to gzip format
    # - 1: compress fast
    # - 7: compress more, but still fast (default)
    # - 8: compress more, slower
    # - 9: compress best, very slow
    def GZip.gzip s, level = DEFAULT_GZIP_LEVEL
      Zlib::Deflate.new(level).deflate s, Zlib::FINISH
    end
    
  end
  
end
