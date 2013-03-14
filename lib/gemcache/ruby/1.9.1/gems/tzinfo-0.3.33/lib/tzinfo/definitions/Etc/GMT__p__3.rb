module TZInfo
  module Definitions
    module Etc
      module GMT__p__3
        include TimezoneDefinition
        
        timezone 'Etc/GMT+3' do |tz|
          tz.offset :o0, -10800, 0, :'GMT+3'
          
        end
      end
    end
  end
end
