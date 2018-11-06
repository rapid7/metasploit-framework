# encoding: UTF-8

# This file contains data derived from the IANA Time Zone Database
# (http://www.iana.org/time-zones).

module TZInfo
  module Data
    module Definitions
      module Asia
        module Tokyo
          include TimezoneDefinition
          
          timezone 'Asia/Tokyo' do |tz|
            tz.offset :o0, 33539, 0, :LMT
            tz.offset :o1, 32400, 0, :JST
            tz.offset :o2, 32400, 3600, :JDT
            
            tz.transition 1887, 12, :o1, -2587712400, 19285097, 8
            tz.transition 1948, 5, :o2, -683802000, 19461385, 8
            tz.transition 1948, 9, :o1, -672310800, 19462449, 8
            tz.transition 1949, 4, :o2, -654771600, 19464073, 8
            tz.transition 1949, 9, :o1, -640861200, 19465361, 8
            tz.transition 1950, 5, :o2, -620298000, 19467265, 8
            tz.transition 1950, 9, :o1, -609411600, 19468273, 8
            tz.transition 1951, 5, :o2, -588848400, 19470177, 8
            tz.transition 1951, 9, :o1, -577962000, 19471185, 8
          end
        end
      end
    end
  end
end
