module TZInfo
  module Definitions
    module America
      module Guayaquil
        include TimezoneDefinition
        
        timezone 'America/Guayaquil' do |tz|
          tz.offset :o0, -19160, 0, :LMT
          tz.offset :o1, -18840, 0, :QMT
          tz.offset :o2, -18000, 0, :ECT
          
          tz.transition 1890, 1, :o1, 5208556439, 2160
          tz.transition 1931, 1, :o2, 1746966757, 720
        end
      end
    end
  end
end
