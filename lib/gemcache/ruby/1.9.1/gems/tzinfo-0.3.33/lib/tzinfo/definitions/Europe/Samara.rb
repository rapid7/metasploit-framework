module TZInfo
  module Definitions
    module Europe
      module Samara
        include TimezoneDefinition
        
        timezone 'Europe/Samara' do |tz|
          tz.offset :o0, 12036, 0, :LMT
          tz.offset :o1, 10800, 0, :SAMT
          tz.offset :o2, 14400, 0, :SAMT
          tz.offset :o3, 14400, 0, :KUYT
          tz.offset :o4, 14400, 3600, :KUYST
          tz.offset :o5, 10800, 3600, :KUYST
          tz.offset :o6, 10800, 0, :KUYT
          tz.offset :o7, 7200, 3600, :KUYST
          tz.offset :o8, 14400, 3600, :SAMST
          tz.offset :o9, 10800, 3600, :SAMST
          
          tz.transition 1919, 6, :o1, 17439411197, 7200
          tz.transition 1930, 6, :o2, 19409187, 8
          tz.transition 1935, 1, :o3, 7283488, 3
          tz.transition 1981, 3, :o4, 354916800
          tz.transition 1981, 9, :o3, 370724400
          tz.transition 1982, 3, :o4, 386452800
          tz.transition 1982, 9, :o3, 402260400
          tz.transition 1983, 3, :o4, 417988800
          tz.transition 1983, 9, :o3, 433796400
          tz.transition 1984, 3, :o4, 449611200
          tz.transition 1984, 9, :o3, 465343200
          tz.transition 1985, 3, :o4, 481068000
          tz.transition 1985, 9, :o3, 496792800
          tz.transition 1986, 3, :o4, 512517600
          tz.transition 1986, 9, :o3, 528242400
          tz.transition 1987, 3, :o4, 543967200
          tz.transition 1987, 9, :o3, 559692000
          tz.transition 1988, 3, :o4, 575416800
          tz.transition 1988, 9, :o3, 591141600
          tz.transition 1989, 3, :o5, 606866400
          tz.transition 1989, 9, :o6, 622594800
          tz.transition 1990, 3, :o5, 638319600
          tz.transition 1990, 9, :o6, 654649200
          tz.transition 1991, 3, :o7, 670374000
          tz.transition 1991, 9, :o6, 686102400
          tz.transition 1991, 10, :o2, 687916800
          tz.transition 1992, 3, :o8, 701809200
          tz.transition 1992, 9, :o2, 717530400
          tz.transition 1993, 3, :o8, 733269600
          tz.transition 1993, 9, :o2, 748994400
          tz.transition 1994, 3, :o8, 764719200
          tz.transition 1994, 9, :o2, 780444000
          tz.transition 1995, 3, :o8, 796168800
          tz.transition 1995, 9, :o2, 811893600
          tz.transition 1996, 3, :o8, 828223200
          tz.transition 1996, 10, :o2, 846367200
          tz.transition 1997, 3, :o8, 859672800
          tz.transition 1997, 10, :o2, 877816800
          tz.transition 1998, 3, :o8, 891122400
          tz.transition 1998, 10, :o2, 909266400
          tz.transition 1999, 3, :o8, 922572000
          tz.transition 1999, 10, :o2, 941320800
          tz.transition 2000, 3, :o8, 954021600
          tz.transition 2000, 10, :o2, 972770400
          tz.transition 2001, 3, :o8, 985471200
          tz.transition 2001, 10, :o2, 1004220000
          tz.transition 2002, 3, :o8, 1017525600
          tz.transition 2002, 10, :o2, 1035669600
          tz.transition 2003, 3, :o8, 1048975200
          tz.transition 2003, 10, :o2, 1067119200
          tz.transition 2004, 3, :o8, 1080424800
          tz.transition 2004, 10, :o2, 1099173600
          tz.transition 2005, 3, :o8, 1111874400
          tz.transition 2005, 10, :o2, 1130623200
          tz.transition 2006, 3, :o8, 1143324000
          tz.transition 2006, 10, :o2, 1162072800
          tz.transition 2007, 3, :o8, 1174773600
          tz.transition 2007, 10, :o2, 1193522400
          tz.transition 2008, 3, :o8, 1206828000
          tz.transition 2008, 10, :o2, 1224972000
          tz.transition 2009, 3, :o8, 1238277600
          tz.transition 2009, 10, :o2, 1256421600
          tz.transition 2010, 3, :o9, 1269727200
          tz.transition 2010, 10, :o1, 1288479600
          tz.transition 2011, 3, :o2, 1301180400
        end
      end
    end
  end
end
