module TZInfo
  module Definitions
    module Pacific
      module Kosrae
        include TimezoneDefinition
        
        timezone 'Pacific/Kosrae' do |tz|
          tz.offset :o0, 39116, 0, :LMT
          tz.offset :o1, 39600, 0, :KOST
          tz.offset :o2, 43200, 0, :KOST
          
          tz.transition 1900, 12, :o1, 52172317021, 21600
          tz.transition 1969, 9, :o2, 58571881, 24
          tz.transition 1998, 12, :o1, 915105600
        end
      end
    end
  end
end
