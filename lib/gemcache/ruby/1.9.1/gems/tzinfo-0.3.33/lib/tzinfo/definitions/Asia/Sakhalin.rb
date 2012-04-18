module TZInfo
  module Definitions
    module Asia
      module Sakhalin
        include TimezoneDefinition
        
        timezone 'Asia/Sakhalin' do |tz|
          tz.offset :o0, 34248, 0, :LMT
          tz.offset :o1, 32400, 0, :CJT
          tz.offset :o2, 32400, 0, :JST
          tz.offset :o3, 39600, 0, :SAKT
          tz.offset :o4, 39600, 3600, :SAKST
          tz.offset :o5, 36000, 3600, :SAKST
          tz.offset :o6, 36000, 0, :SAKT
          
          tz.transition 1905, 8, :o1, 8701488373, 3600
          tz.transition 1937, 12, :o2, 19431193, 8
          tz.transition 1945, 8, :o3, 19453537, 8
          tz.transition 1981, 3, :o4, 354891600
          tz.transition 1981, 9, :o3, 370699200
          tz.transition 1982, 3, :o4, 386427600
          tz.transition 1982, 9, :o3, 402235200
          tz.transition 1983, 3, :o4, 417963600
          tz.transition 1983, 9, :o3, 433771200
          tz.transition 1984, 3, :o4, 449586000
          tz.transition 1984, 9, :o3, 465318000
          tz.transition 1985, 3, :o4, 481042800
          tz.transition 1985, 9, :o3, 496767600
          tz.transition 1986, 3, :o4, 512492400
          tz.transition 1986, 9, :o3, 528217200
          tz.transition 1987, 3, :o4, 543942000
          tz.transition 1987, 9, :o3, 559666800
          tz.transition 1988, 3, :o4, 575391600
          tz.transition 1988, 9, :o3, 591116400
          tz.transition 1989, 3, :o4, 606841200
          tz.transition 1989, 9, :o3, 622566000
          tz.transition 1990, 3, :o4, 638290800
          tz.transition 1990, 9, :o3, 654620400
          tz.transition 1991, 3, :o5, 670345200
          tz.transition 1991, 9, :o6, 686073600
          tz.transition 1992, 1, :o3, 695750400
          tz.transition 1992, 3, :o4, 701784000
          tz.transition 1992, 9, :o3, 717505200
          tz.transition 1993, 3, :o4, 733244400
          tz.transition 1993, 9, :o3, 748969200
          tz.transition 1994, 3, :o4, 764694000
          tz.transition 1994, 9, :o3, 780418800
          tz.transition 1995, 3, :o4, 796143600
          tz.transition 1995, 9, :o3, 811868400
          tz.transition 1996, 3, :o4, 828198000
          tz.transition 1996, 10, :o3, 846342000
          tz.transition 1997, 3, :o5, 859647600
          tz.transition 1997, 10, :o6, 877795200
          tz.transition 1998, 3, :o5, 891100800
          tz.transition 1998, 10, :o6, 909244800
          tz.transition 1999, 3, :o5, 922550400
          tz.transition 1999, 10, :o6, 941299200
          tz.transition 2000, 3, :o5, 954000000
          tz.transition 2000, 10, :o6, 972748800
          tz.transition 2001, 3, :o5, 985449600
          tz.transition 2001, 10, :o6, 1004198400
          tz.transition 2002, 3, :o5, 1017504000
          tz.transition 2002, 10, :o6, 1035648000
          tz.transition 2003, 3, :o5, 1048953600
          tz.transition 2003, 10, :o6, 1067097600
          tz.transition 2004, 3, :o5, 1080403200
          tz.transition 2004, 10, :o6, 1099152000
          tz.transition 2005, 3, :o5, 1111852800
          tz.transition 2005, 10, :o6, 1130601600
          tz.transition 2006, 3, :o5, 1143302400
          tz.transition 2006, 10, :o6, 1162051200
          tz.transition 2007, 3, :o5, 1174752000
          tz.transition 2007, 10, :o6, 1193500800
          tz.transition 2008, 3, :o5, 1206806400
          tz.transition 2008, 10, :o6, 1224950400
          tz.transition 2009, 3, :o5, 1238256000
          tz.transition 2009, 10, :o6, 1256400000
          tz.transition 2010, 3, :o5, 1269705600
          tz.transition 2010, 10, :o6, 1288454400
          tz.transition 2011, 3, :o3, 1301155200
        end
      end
    end
  end
end
