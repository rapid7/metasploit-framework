module TZInfo
  module Definitions
    module Asia
      module Aqtau
        include TimezoneDefinition
        
        timezone 'Asia/Aqtau' do |tz|
          tz.offset :o0, 12064, 0, :LMT
          tz.offset :o1, 14400, 0, :FORT
          tz.offset :o2, 18000, 0, :FORT
          tz.offset :o3, 18000, 0, :SHET
          tz.offset :o4, 21600, 0, :SHET
          tz.offset :o5, 18000, 3600, :SHEST
          tz.offset :o6, 18000, 0, :AQTT
          tz.offset :o7, 18000, 3600, :AQTST
          tz.offset :o8, 14400, 3600, :AQTST
          tz.offset :o9, 14400, 0, :AQTT
          
          tz.transition 1924, 5, :o1, 6544549873, 2700
          tz.transition 1930, 6, :o2, 7278445, 3
          tz.transition 1962, 12, :o3, 58512727, 24
          tz.transition 1981, 9, :o4, 370724400
          tz.transition 1982, 3, :o5, 386445600
          tz.transition 1982, 9, :o3, 402256800
          tz.transition 1983, 3, :o5, 417985200
          tz.transition 1983, 9, :o3, 433792800
          tz.transition 1984, 3, :o5, 449607600
          tz.transition 1984, 9, :o3, 465339600
          tz.transition 1985, 3, :o5, 481064400
          tz.transition 1985, 9, :o3, 496789200
          tz.transition 1986, 3, :o5, 512514000
          tz.transition 1986, 9, :o3, 528238800
          tz.transition 1987, 3, :o5, 543963600
          tz.transition 1987, 9, :o3, 559688400
          tz.transition 1988, 3, :o5, 575413200
          tz.transition 1988, 9, :o3, 591138000
          tz.transition 1989, 3, :o5, 606862800
          tz.transition 1989, 9, :o3, 622587600
          tz.transition 1990, 3, :o5, 638312400
          tz.transition 1990, 9, :o3, 654642000
          tz.transition 1991, 12, :o6, 692823600
          tz.transition 1992, 3, :o7, 701805600
          tz.transition 1992, 9, :o6, 717526800
          tz.transition 1993, 3, :o7, 733266000
          tz.transition 1993, 9, :o6, 748990800
          tz.transition 1994, 3, :o7, 764715600
          tz.transition 1994, 9, :o6, 780440400
          tz.transition 1995, 3, :o8, 796165200
          tz.transition 1995, 9, :o9, 811893600
          tz.transition 1996, 3, :o8, 828223200
          tz.transition 1996, 10, :o9, 846367200
          tz.transition 1997, 3, :o8, 859672800
          tz.transition 1997, 10, :o9, 877816800
          tz.transition 1998, 3, :o8, 891122400
          tz.transition 1998, 10, :o9, 909266400
          tz.transition 1999, 3, :o8, 922572000
          tz.transition 1999, 10, :o9, 941320800
          tz.transition 2000, 3, :o8, 954021600
          tz.transition 2000, 10, :o9, 972770400
          tz.transition 2001, 3, :o8, 985471200
          tz.transition 2001, 10, :o9, 1004220000
          tz.transition 2002, 3, :o8, 1017525600
          tz.transition 2002, 10, :o9, 1035669600
          tz.transition 2003, 3, :o8, 1048975200
          tz.transition 2003, 10, :o9, 1067119200
          tz.transition 2004, 3, :o8, 1080424800
          tz.transition 2004, 10, :o9, 1099173600
          tz.transition 2005, 3, :o6, 1110830400
        end
      end
    end
  end
end
