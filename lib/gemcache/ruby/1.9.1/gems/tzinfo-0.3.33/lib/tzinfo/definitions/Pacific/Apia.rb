module TZInfo
  module Definitions
    module Pacific
      module Apia
        include TimezoneDefinition
        
        timezone 'Pacific/Apia' do |tz|
          tz.offset :o0, 45184, 0, :LMT
          tz.offset :o1, -41216, 0, :LMT
          tz.offset :o2, -41400, 0, :SAMT
          tz.offset :o3, -39600, 0, :WST
          tz.offset :o4, -39600, 3600, :WSDT
          tz.offset :o5, 46800, 3600, :WSDT
          tz.offset :o6, 46800, 0, :WST
          
          tz.transition 1879, 7, :o1, 3250172219, 1350
          tz.transition 1911, 1, :o2, 3265701269, 1350
          tz.transition 1950, 1, :o3, 116797583, 48
          tz.transition 2010, 9, :o4, 1285498800
          tz.transition 2011, 4, :o3, 1301752800
          tz.transition 2011, 9, :o4, 1316872800
          tz.transition 2011, 12, :o5, 1325239200
          tz.transition 2012, 3, :o6, 1333202400
        end
      end
    end
  end
end
