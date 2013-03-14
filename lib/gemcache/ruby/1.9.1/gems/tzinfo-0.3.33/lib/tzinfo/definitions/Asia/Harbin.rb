module TZInfo
  module Definitions
    module Asia
      module Harbin
        include TimezoneDefinition
        
        timezone 'Asia/Harbin' do |tz|
          tz.offset :o0, 30404, 0, :LMT
          tz.offset :o1, 30600, 0, :CHAT
          tz.offset :o2, 28800, 0, :CST
          tz.offset :o3, 32400, 0, :CHAT
          tz.offset :o4, 28800, 3600, :CDT
          
          tz.transition 1927, 12, :o1, 52385316799, 21600
          tz.transition 1932, 2, :o2, 116484823, 48
          tz.transition 1939, 12, :o3, 14577775, 6
          tz.transition 1966, 4, :o1, 19513969, 8
          tz.transition 1980, 4, :o2, 325956600
          tz.transition 1986, 5, :o4, 515520000
          tz.transition 1986, 9, :o2, 527007600
          tz.transition 1987, 4, :o4, 545155200
          tz.transition 1987, 9, :o2, 558457200
          tz.transition 1988, 4, :o4, 576604800
          tz.transition 1988, 9, :o2, 589906800
          tz.transition 1989, 4, :o4, 608659200
          tz.transition 1989, 9, :o2, 621961200
          tz.transition 1990, 4, :o4, 640108800
          tz.transition 1990, 9, :o2, 653410800
          tz.transition 1991, 4, :o4, 671558400
          tz.transition 1991, 9, :o2, 684860400
        end
      end
    end
  end
end
