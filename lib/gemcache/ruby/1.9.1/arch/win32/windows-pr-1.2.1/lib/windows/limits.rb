module Windows
  module Limits
    private

    MINCHAR  = 0x80
    MAXCHAR  = 0x7f
    MINSHORT = 0x8000
    MAXSHORT = 0x7fff
    MINLONG  = 0x80000000
    MAXLONG  = 0x7fffffff
    MAXBYTE  = 0xff
    MAXWORD  = 0xffff
    MAXDWORD = 0xffffffff
      
    # For wide character functions the actual path limit is actually 32k
    # for most functions that deal with paths, but in the interests of not
    # wasting huge chunks of memory on buffers I limit it to 1k, which
    # should be more than enough in practice.
    #
    if RUBY_VERSION.to_f >= 1.9
      if __ENCODING__.name == 'UTF-8'
        MAXPATH = 1024
      else
        MAXPATH = 256
      end
    else
      if $KCODE == 'UTF8'
        MAXPATH = 1024
      else
        MAXPATH = 256
      end
    end
  end
end 
