module TZInfo
  module Definitions
    module Etc
      module GMT__m__1
        include TimezoneDefinition
        
        timezone 'Etc/GMT-1' do |tz|
          tz.offset :o0, 3600, 0, :'GMT-1'
          
        end
      end
    end
  end
end
