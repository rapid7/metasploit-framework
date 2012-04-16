module TZInfo
  module Definitions
    module Etc
      module GMT__p__4
        include TimezoneDefinition
        
        timezone 'Etc/GMT+4' do |tz|
          tz.offset :o0, -14400, 0, :'GMT+4'
          
        end
      end
    end
  end
end
