module TZInfo
  module Definitions
    module Asia
      module Ashgabat
        include TimezoneDefinition
        
        timezone 'Asia/Ashgabat' do |tz|
          tz.offset :o0, 14012, 0, :LMT
          tz.offset :o1, 14400, 0, :ASHT
          tz.offset :o2, 18000, 0, :ASHT
          tz.offset :o3, 18000, 3600, :ASHST
          tz.offset :o4, 14400, 3600, :ASHST
          tz.offset :o5, 14400, 0, :TMT
          tz.offset :o6, 18000, 0, :TMT
          
          tz.transition 1924, 5, :o1, 52356398497, 21600
          tz.transition 1930, 6, :o2, 7278445, 3
          tz.transition 1981, 3, :o3, 354913200
          tz.transition 1981, 9, :o2, 370720800
          tz.transition 1982, 3, :o3, 386449200
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
          tz.transition 1991, 3, :o4, 670366800
          tz.transition 1991, 9, :o1, 686095200
          tz.transition 1991, 10, :o5, 688507200
          tz.transition 1992, 1, :o6, 695772000
        end
      end
    end
  end
end
