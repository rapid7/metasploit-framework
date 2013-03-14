module TZInfo
  module Definitions
    module America
      module Port__m__au__m__Prince
        include TimezoneDefinition
        
        timezone 'America/Port-au-Prince' do |tz|
          tz.offset :o0, -17360, 0, :LMT
          tz.offset :o1, -17340, 0, :PPMT
          tz.offset :o2, -18000, 0, :EST
          tz.offset :o3, -18000, 3600, :EDT
          
          tz.transition 1890, 1, :o1, 2604278197, 1080
          tz.transition 1917, 1, :o2, 3486604609, 1440
          tz.transition 1983, 5, :o3, 421218000
          tz.transition 1983, 10, :o2, 436334400
          tz.transition 1984, 4, :o3, 452062800
          tz.transition 1984, 10, :o2, 467784000
          tz.transition 1985, 4, :o3, 483512400
          tz.transition 1985, 10, :o2, 499233600
          tz.transition 1986, 4, :o3, 514962000
          tz.transition 1986, 10, :o2, 530683200
          tz.transition 1987, 4, :o3, 546411600
          tz.transition 1987, 10, :o2, 562132800
          tz.transition 1988, 4, :o3, 576050400
          tz.transition 1988, 10, :o2, 594194400
          tz.transition 1989, 4, :o3, 607500000
          tz.transition 1989, 10, :o2, 625644000
          tz.transition 1990, 4, :o3, 638949600
          tz.transition 1990, 10, :o2, 657093600
          tz.transition 1991, 4, :o3, 671004000
          tz.transition 1991, 10, :o2, 688543200
          tz.transition 1992, 4, :o3, 702453600
          tz.transition 1992, 10, :o2, 719992800
          tz.transition 1993, 4, :o3, 733903200
          tz.transition 1993, 10, :o2, 752047200
          tz.transition 1994, 4, :o3, 765352800
          tz.transition 1994, 10, :o2, 783496800
          tz.transition 1995, 4, :o3, 796802400
          tz.transition 1995, 10, :o2, 814946400
          tz.transition 1996, 4, :o3, 828856800
          tz.transition 1996, 10, :o2, 846396000
          tz.transition 1997, 4, :o3, 860306400
          tz.transition 1997, 10, :o2, 877845600
          tz.transition 2005, 4, :o3, 1112504400
          tz.transition 2005, 10, :o2, 1130644800
          tz.transition 2006, 4, :o3, 1143954000
          tz.transition 2006, 10, :o2, 1162094400
          tz.transition 2012, 3, :o3, 1331449200
          tz.transition 2012, 11, :o2, 1352008800
        end
      end
    end
  end
end
