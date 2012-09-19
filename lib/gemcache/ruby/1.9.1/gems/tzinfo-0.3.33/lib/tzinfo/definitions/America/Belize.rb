module TZInfo
  module Definitions
    module America
      module Belize
        include TimezoneDefinition
        
        timezone 'America/Belize' do |tz|
          tz.offset :o0, -21168, 0, :LMT
          tz.offset :o1, -21600, 0, :CST
          tz.offset :o2, -21600, 1800, :CHDT
          tz.offset :o3, -21600, 3600, :CDT
          
          tz.transition 1912, 4, :o1, 483898749, 200
          tz.transition 1918, 10, :o2, 9687491, 4
          tz.transition 1919, 2, :o1, 116255939, 48
          tz.transition 1919, 10, :o2, 9688947, 4
          tz.transition 1920, 2, :o1, 116273747, 48
          tz.transition 1920, 10, :o2, 9690403, 4
          tz.transition 1921, 2, :o1, 116291219, 48
          tz.transition 1921, 10, :o2, 9691859, 4
          tz.transition 1922, 2, :o1, 116308691, 48
          tz.transition 1922, 10, :o2, 9693343, 4
          tz.transition 1923, 2, :o1, 116326163, 48
          tz.transition 1923, 10, :o2, 9694799, 4
          tz.transition 1924, 2, :o1, 116343635, 48
          tz.transition 1924, 10, :o2, 9696255, 4
          tz.transition 1925, 2, :o1, 116361443, 48
          tz.transition 1925, 10, :o2, 9697711, 4
          tz.transition 1926, 2, :o1, 116378915, 48
          tz.transition 1926, 10, :o2, 9699167, 4
          tz.transition 1927, 2, :o1, 116396387, 48
          tz.transition 1927, 10, :o2, 9700623, 4
          tz.transition 1928, 2, :o1, 116413859, 48
          tz.transition 1928, 10, :o2, 9702107, 4
          tz.transition 1929, 2, :o1, 116431331, 48
          tz.transition 1929, 10, :o2, 9703563, 4
          tz.transition 1930, 2, :o1, 116448803, 48
          tz.transition 1930, 10, :o2, 9705019, 4
          tz.transition 1931, 2, :o1, 116466611, 48
          tz.transition 1931, 10, :o2, 9706475, 4
          tz.transition 1932, 2, :o1, 116484083, 48
          tz.transition 1932, 10, :o2, 9707931, 4
          tz.transition 1933, 2, :o1, 116501555, 48
          tz.transition 1933, 10, :o2, 9709415, 4
          tz.transition 1934, 2, :o1, 116519027, 48
          tz.transition 1934, 10, :o2, 9710871, 4
          tz.transition 1935, 2, :o1, 116536499, 48
          tz.transition 1935, 10, :o2, 9712327, 4
          tz.transition 1936, 2, :o1, 116553971, 48
          tz.transition 1936, 10, :o2, 9713783, 4
          tz.transition 1937, 2, :o1, 116571779, 48
          tz.transition 1937, 10, :o2, 9715239, 4
          tz.transition 1938, 2, :o1, 116589251, 48
          tz.transition 1938, 10, :o2, 9716695, 4
          tz.transition 1939, 2, :o1, 116606723, 48
          tz.transition 1939, 10, :o2, 9718179, 4
          tz.transition 1940, 2, :o1, 116624195, 48
          tz.transition 1940, 10, :o2, 9719635, 4
          tz.transition 1941, 2, :o1, 116641667, 48
          tz.transition 1941, 10, :o2, 9721091, 4
          tz.transition 1942, 2, :o1, 116659475, 48
          tz.transition 1942, 10, :o2, 9722547, 4
          tz.transition 1943, 2, :o1, 116676947, 48
          tz.transition 1973, 12, :o3, 123919200
          tz.transition 1974, 2, :o1, 129618000
          tz.transition 1982, 12, :o3, 409039200
          tz.transition 1983, 2, :o1, 413874000
        end
      end
    end
  end
end
