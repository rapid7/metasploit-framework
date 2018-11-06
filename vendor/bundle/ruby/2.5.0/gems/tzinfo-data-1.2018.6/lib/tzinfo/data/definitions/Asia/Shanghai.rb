# encoding: UTF-8

# This file contains data derived from the IANA Time Zone Database
# (http://www.iana.org/time-zones).

module TZInfo
  module Data
    module Definitions
      module Asia
        module Shanghai
          include TimezoneDefinition
          
          timezone 'Asia/Shanghai' do |tz|
            tz.offset :o0, 29143, 0, :LMT
            tz.offset :o1, 28800, 0, :CST
            tz.offset :o2, 28800, 3600, :CDT
            
            tz.transition 1900, 12, :o1, -2177481943, 208689278057, 86400
            tz.transition 1940, 5, :o2, -933667200, 14578687, 6
            tz.transition 1940, 10, :o1, -922093200, 19439321, 8
            tz.transition 1941, 3, :o2, -908870400, 14580409, 6
            tz.transition 1941, 11, :o1, -888829200, 19442401, 8
            tz.transition 1942, 1, :o2, -881049600, 14582341, 6
            tz.transition 1945, 9, :o1, -767869200, 19453601, 8
            tz.transition 1946, 5, :o2, -745833600, 14591731, 6
            tz.transition 1946, 9, :o1, -733827600, 19456753, 8
            tz.transition 1947, 4, :o2, -716889600, 14593741, 6
            tz.transition 1947, 10, :o1, -699613200, 19459921, 8
            tz.transition 1948, 4, :o2, -683884800, 14596033, 6
            tz.transition 1948, 9, :o1, -670669200, 19462601, 8
            tz.transition 1949, 4, :o2, -652348800, 14598223, 6
            tz.transition 1949, 5, :o1, -650019600, 19464513, 8
            tz.transition 1986, 5, :o2, 515527200
            tz.transition 1986, 9, :o1, 527014800
            tz.transition 1987, 4, :o2, 545162400
            tz.transition 1987, 9, :o1, 558464400
            tz.transition 1988, 4, :o2, 577216800
            tz.transition 1988, 9, :o1, 589914000
            tz.transition 1989, 4, :o2, 608666400
            tz.transition 1989, 9, :o1, 621968400
            tz.transition 1990, 4, :o2, 640116000
            tz.transition 1990, 9, :o1, 653418000
            tz.transition 1991, 4, :o2, 671565600
            tz.transition 1991, 9, :o1, 684867600
          end
        end
      end
    end
  end
end
