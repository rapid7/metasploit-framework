module TZInfo
  module Definitions
    module Asia
      module Qyzylorda
        include TimezoneDefinition
        
        timezone 'Asia/Qyzylorda' do |tz|
          tz.offset :o0, 15712, 0, :LMT
          tz.offset :o1, 14400, 0, :KIZT
          tz.offset :o2, 18000, 0, :KIZT
          tz.offset :o3, 18000, 3600, :KIZST
          tz.offset :o4, 21600, 0, :KIZT
          tz.offset :o5, 18000, 0, :QYZT
          tz.offset :o6, 21600, 0, :QYZT
          tz.offset :o7, 21600, 3600, :QYZST
          
          tz.transition 1924, 5, :o1, 6544549759, 2700
          tz.transition 1930, 6, :o2, 7278445, 3
          tz.transition 1981, 3, :o3, 354913200
          tz.transition 1981, 9, :o4, 370720800
          tz.transition 1982, 3, :o3, 386445600
          tz.transition 1982, 9, :o2, 402256800
          tz.transition 1983, 3, :o3, 417985200
          tz.transition 1983, 9, :o2, 433792800
          tz.transition 1984, 3, :o3, 449607600
          tz.transition 1984, 9, :o2, 465339600
          tz.transition 1985, 3, :o3, 481064400
          tz.transition 1985, 9, :o2, 496789200
          tz.transition 1986, 3, :o3, 512514000
          tz.transition 1986, 9, :o2, 528238800
          tz.transition 1987, 3, :o3, 543963600
          tz.transition 1987, 9, :o2, 559688400
          tz.transition 1988, 3, :o3, 575413200
          tz.transition 1988, 9, :o2, 591138000
          tz.transition 1989, 3, :o3, 606862800
          tz.transition 1989, 9, :o2, 622587600
          tz.transition 1990, 3, :o3, 638312400
          tz.transition 1990, 9, :o2, 654642000
          tz.transition 1991, 12, :o5, 692823600
          tz.transition 1992, 1, :o6, 695768400
          tz.transition 1992, 3, :o7, 701802000
          tz.transition 1992, 9, :o6, 717523200
          tz.transition 1993, 3, :o7, 733262400
          tz.transition 1993, 9, :o6, 748987200
          tz.transition 1994, 3, :o7, 764712000
          tz.transition 1994, 9, :o6, 780436800
          tz.transition 1995, 3, :o7, 796161600
          tz.transition 1995, 9, :o6, 811886400
          tz.transition 1996, 3, :o7, 828216000
          tz.transition 1996, 10, :o6, 846360000
          tz.transition 1997, 3, :o7, 859665600
          tz.transition 1997, 10, :o6, 877809600
          tz.transition 1998, 3, :o7, 891115200
          tz.transition 1998, 10, :o6, 909259200
          tz.transition 1999, 3, :o7, 922564800
          tz.transition 1999, 10, :o6, 941313600
          tz.transition 2000, 3, :o7, 954014400
          tz.transition 2000, 10, :o6, 972763200
          tz.transition 2001, 3, :o7, 985464000
          tz.transition 2001, 10, :o6, 1004212800
          tz.transition 2002, 3, :o7, 1017518400
          tz.transition 2002, 10, :o6, 1035662400
          tz.transition 2003, 3, :o7, 1048968000
          tz.transition 2003, 10, :o6, 1067112000
          tz.transition 2004, 3, :o7, 1080417600
          tz.transition 2004, 10, :o6, 1099166400
        end
      end
    end
  end
end
