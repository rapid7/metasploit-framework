module TZInfo
  module Definitions
    module Antarctica
      module DumontDUrville
        include TimezoneDefinition
        
        timezone 'Antarctica/DumontDUrville' do |tz|
          tz.offset :o0, 0, 0, :zzz
          tz.offset :o1, 36000, 0, :PMT
          tz.offset :o2, 36000, 0, :DDUT
          
          tz.transition 1947, 1, :o1, 4864373, 2
          tz.transition 1952, 1, :o0, 29208301, 12
          tz.transition 1956, 11, :o2, 4871557, 2
        end
      end
    end
  end
end
