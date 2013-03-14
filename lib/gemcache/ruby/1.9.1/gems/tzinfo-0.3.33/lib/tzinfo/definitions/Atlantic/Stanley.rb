module TZInfo
  module Definitions
    module Atlantic
      module Stanley
        include TimezoneDefinition
        
        timezone 'Atlantic/Stanley' do |tz|
          tz.offset :o0, -13884, 0, :LMT
          tz.offset :o1, -13884, 0, :SMT
          tz.offset :o2, -14400, 0, :FKT
          tz.offset :o3, -14400, 3600, :FKST
          tz.offset :o4, -10800, 0, :FKT
          tz.offset :o5, -10800, 3600, :FKST
          tz.offset :o6, -10800, 0, :FKST
          
          tz.transition 1890, 1, :o1, 17361854357, 7200
          tz.transition 1912, 3, :o2, 17420210357, 7200
          tz.transition 1937, 9, :o3, 7286408, 3
          tz.transition 1938, 3, :o2, 19431821, 8
          tz.transition 1938, 9, :o3, 7287500, 3
          tz.transition 1939, 3, :o2, 19434733, 8
          tz.transition 1939, 10, :o3, 7288613, 3
          tz.transition 1940, 3, :o2, 19437701, 8
          tz.transition 1940, 9, :o3, 7289705, 3
          tz.transition 1941, 3, :o2, 19440613, 8
          tz.transition 1941, 9, :o3, 7290797, 3
          tz.transition 1942, 3, :o2, 19443525, 8
          tz.transition 1942, 9, :o3, 7291889, 3
          tz.transition 1943, 1, :o2, 19445805, 8
          tz.transition 1983, 5, :o4, 420609600
          tz.transition 1983, 9, :o5, 433306800
          tz.transition 1984, 4, :o4, 452052000
          tz.transition 1984, 9, :o5, 464151600
          tz.transition 1985, 4, :o4, 483501600
          tz.transition 1985, 9, :o3, 495601200
          tz.transition 1986, 4, :o2, 514350000
          tz.transition 1986, 9, :o3, 527054400
          tz.transition 1987, 4, :o2, 545799600
          tz.transition 1987, 9, :o3, 558504000
          tz.transition 1988, 4, :o2, 577249200
          tz.transition 1988, 9, :o3, 589953600
          tz.transition 1989, 4, :o2, 608698800
          tz.transition 1989, 9, :o3, 621403200
          tz.transition 1990, 4, :o2, 640753200
          tz.transition 1990, 9, :o3, 652852800
          tz.transition 1991, 4, :o2, 672202800
          tz.transition 1991, 9, :o3, 684907200
          tz.transition 1992, 4, :o2, 703652400
          tz.transition 1992, 9, :o3, 716356800
          tz.transition 1993, 4, :o2, 735102000
          tz.transition 1993, 9, :o3, 747806400
          tz.transition 1994, 4, :o2, 766551600
          tz.transition 1994, 9, :o3, 779256000
          tz.transition 1995, 4, :o2, 798001200
          tz.transition 1995, 9, :o3, 810705600
          tz.transition 1996, 4, :o2, 830055600
          tz.transition 1996, 9, :o3, 842760000
          tz.transition 1997, 4, :o2, 861505200
          tz.transition 1997, 9, :o3, 874209600
          tz.transition 1998, 4, :o2, 892954800
          tz.transition 1998, 9, :o3, 905659200
          tz.transition 1999, 4, :o2, 924404400
          tz.transition 1999, 9, :o3, 937108800
          tz.transition 2000, 4, :o2, 955854000
          tz.transition 2000, 9, :o3, 968558400
          tz.transition 2001, 4, :o2, 987310800
          tz.transition 2001, 9, :o3, 999410400
          tz.transition 2002, 4, :o2, 1019365200
          tz.transition 2002, 9, :o3, 1030860000
          tz.transition 2003, 4, :o2, 1050814800
          tz.transition 2003, 9, :o3, 1062914400
          tz.transition 2004, 4, :o2, 1082264400
          tz.transition 2004, 9, :o3, 1094364000
          tz.transition 2005, 4, :o2, 1113714000
          tz.transition 2005, 9, :o3, 1125813600
          tz.transition 2006, 4, :o2, 1145163600
          tz.transition 2006, 9, :o3, 1157263200
          tz.transition 2007, 4, :o2, 1176613200
          tz.transition 2007, 9, :o3, 1188712800
          tz.transition 2008, 4, :o2, 1208667600
          tz.transition 2008, 9, :o3, 1220767200
          tz.transition 2009, 4, :o2, 1240117200
          tz.transition 2009, 9, :o3, 1252216800
          tz.transition 2010, 4, :o2, 1271566800
          tz.transition 2010, 9, :o6, 1283666400
        end
      end
    end
  end
end
