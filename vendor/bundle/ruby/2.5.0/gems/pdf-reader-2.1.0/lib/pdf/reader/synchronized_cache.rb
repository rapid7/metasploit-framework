# encoding: utf-8

# utilities.rb : General-purpose utility classes which don't fit anywhere else
#
# Copyright August 2012, Alex Dowad. All Rights Reserved.
#
# This is free software. Please see the LICENSE and COPYING files for details.
#
# This was originally written for the prawn gem.

require 'thread'

class PDF::Reader

  # Throughout the pdf-reader codebase, repeated calculations which can benefit
  # from caching are made In some cases, caching and reusing results can not
  # only save CPU cycles but also greatly reduce memory requirements But at the
  # same time, we don't want to throw away thread safety We have two
  # interchangeable thread-safe cache implementations:
  class SynchronizedCache
    def initialize
      @cache = {}
      @mutex = Mutex.new
    end
    def [](key)
      @mutex.synchronize { @cache[key] }
    end
    def []=(key,value)
      @mutex.synchronize { @cache[key] = value }
    end
  end
end
