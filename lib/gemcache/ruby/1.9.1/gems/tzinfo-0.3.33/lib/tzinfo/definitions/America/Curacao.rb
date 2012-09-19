module TZInfo
  module Definitions
    module America
      module Curacao
        include TimezoneDefinition
        
        timezone 'America/Curacao' do |tz|
          tz.offset :o0, -16544, 0, :LMT
          tz.offset :o1, -16200, 0, :ANT
          tz.offset :o2, -14400, 0, :AST
          
          tz.transition 1912, 2, :o1, 6532500667, 2700
          tz.transition 1965, 1, :o2, 39020187, 16
        end
      end
    end
  end
end
