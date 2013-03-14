module TZInfo
  module Definitions
    module Asia
      module Kashgar
        include TimezoneDefinition
        
        timezone 'Asia/Kashgar' do |tz|
          tz.offset :o0, 18236, 0, :LMT
          tz.offset :o1, 19800, 0, :KAST
          tz.offset :o2, 18000, 0, :KAST
          tz.offset :o3, 28800, 0, :CST
          tz.offset :o4, 28800, 3600, :CDT
          
          tz.transition 1927, 12, :o1, 52385319841, 21600
          tz.transition 1939, 12, :o2, 116622205, 48
          tz.transition 1980, 4, :o3, 325969200
          tz.transition 1986, 5, :o4, 515520000
          tz.transition 1986, 9, :o3, 527007600
          tz.transition 1987, 4, :o4, 545155200
          tz.transition 1987, 9, :o3, 558457200
          tz.transition 1988, 4, :o4, 576604800
          tz.transition 1988, 9, :o3, 589906800
          tz.transition 1989, 4, :o4, 608659200
          tz.transition 1989, 9, :o3, 621961200
          tz.transition 1990, 4, :o4, 640108800
          tz.transition 1990, 9, :o3, 653410800
          tz.transition 1991, 4, :o4, 671558400
          tz.transition 1991, 9, :o3, 684860400
        end
      end
    end
  end
end
