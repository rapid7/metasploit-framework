$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'test/unit'
require 'tzinfo'

include TZInfo

class TCTimezoneNewYork < Test::Unit::TestCase
  def test_2004
    #America/New_York  Sun Apr  4 06:59:59 2004 UTC = Sun Apr  4 01:59:59 2004 EST isdst=0 gmtoff=-18000
    #America/New_York  Sun Apr  4 07:00:00 2004 UTC = Sun Apr  4 03:00:00 2004 EDT isdst=1 gmtoff=-14400
    #America/New_York  Sun Oct 31 05:59:59 2004 UTC = Sun Oct 31 01:59:59 2004 EDT isdst=1 gmtoff=-14400
    #America/New_York  Sun Oct 31 06:00:00 2004 UTC = Sun Oct 31 01:00:00 2004 EST isdst=0 gmtoff=-18000
    
    tz = Timezone.get('America/New_York')
    assert_equal(DateTime.new(2004,4,4,1,59,59), tz.utc_to_local(DateTime.new(2004,4,4,6,59,59)))
    assert_equal(DateTime.new(2004,4,4,3,0,0), tz.utc_to_local(DateTime.new(2004,4,4,7,0,0)))    
    assert_equal(DateTime.new(2004,10,31,1,59,59), tz.utc_to_local(DateTime.new(2004,10,31,5,59,59)))
    assert_equal(DateTime.new(2004,10,31,1,0,0), tz.utc_to_local(DateTime.new(2004,10,31,6,0,0)))
    
    assert_equal(DateTime.new(2004,4,4,6,59,59), tz.local_to_utc(DateTime.new(2004,4,4,1,59,59)))
    assert_equal(DateTime.new(2004,4,4,7,0,0), tz.local_to_utc(DateTime.new(2004,4,4,3,0,0)))
    assert_equal(DateTime.new(2004,10,31,5,59,59), tz.local_to_utc(DateTime.new(2004,10,31,1,59,59), true))
    assert_equal(DateTime.new(2004,10,31,6,59,59), tz.local_to_utc(DateTime.new(2004,10,31,1,59,59), false))
    assert_equal(DateTime.new(2004,10,31,5,0,0), tz.local_to_utc(DateTime.new(2004,10,31,1,0,0), true))
    assert_equal(DateTime.new(2004,10,31,6,0,0), tz.local_to_utc(DateTime.new(2004,10,31,1,0,0), false))
    
    assert_raises(PeriodNotFound) { tz.local_to_utc(DateTime.new(2004,4,4,2,0,0)) }
    assert_raises(AmbiguousTime) { tz.local_to_utc(DateTime.new(2004,10,31,1,0,0)) }
    
    assert_equal(:EST, tz.period_for_utc(DateTime.new(2004,4,4,6,59,59)).zone_identifier)
    assert_equal(:EDT, tz.period_for_utc(DateTime.new(2004,4,4,7,0,0)).zone_identifier)
    assert_equal(:EDT, tz.period_for_utc(DateTime.new(2004,10,31,5,59,59)).zone_identifier)
    assert_equal(:EST, tz.period_for_utc(DateTime.new(2004,10,31,6,0,0)).zone_identifier)
    
    assert_equal(:EST, tz.period_for_local(DateTime.new(2004,4,4,1,59,59)).zone_identifier)
    assert_equal(:EDT, tz.period_for_local(DateTime.new(2004,4,4,3,0,0)).zone_identifier)
    assert_equal(:EDT, tz.period_for_local(DateTime.new(2004,10,31,1,59,59), true).zone_identifier)
    assert_equal(:EST, tz.period_for_local(DateTime.new(2004,10,31,1,59,59), false).zone_identifier)
    assert_equal(:EDT, tz.period_for_local(DateTime.new(2004,10,31,1,0,0), true).zone_identifier)
    assert_equal(:EST, tz.period_for_local(DateTime.new(2004,10,31,1,0,0), false).zone_identifier)
    
    assert_equal(-18000, tz.period_for_utc(DateTime.new(2004,4,4,6,59,59)).utc_total_offset)
    assert_equal(-14400, tz.period_for_utc(DateTime.new(2004,4,4,7,0,0)).utc_total_offset)
    assert_equal(-14400, tz.period_for_utc(DateTime.new(2004,10,31,5,59,59)).utc_total_offset)
    assert_equal(-18000, tz.period_for_utc(DateTime.new(2004,10,31,6,0,0)).utc_total_offset)
    
    assert_equal(-18000, tz.period_for_local(DateTime.new(2004,4,4,1,59,59)).utc_total_offset)
    assert_equal(-14400, tz.period_for_local(DateTime.new(2004,4,4,3,0,0)).utc_total_offset)
    assert_equal(-14400, tz.period_for_local(DateTime.new(2004,10,31,1,59,59), true).utc_total_offset)
    assert_equal(-18000, tz.period_for_local(DateTime.new(2004,10,31,1,59,59), false).utc_total_offset)
    assert_equal(-14400, tz.period_for_local(DateTime.new(2004,10,31,1,0,0), true).utc_total_offset)
    assert_equal(-18000, tz.period_for_local(DateTime.new(2004,10,31,1,0,0), false).utc_total_offset)
  end     

  def test_1957
    #America/New_York  Sun Apr 28 06:59:59 1957 UTC = Sun Apr 28 01:59:59 1957 EST isdst=0 gmtoff=-18000
    #America/New_York  Sun Apr 28 07:00:00 1957 UTC = Sun Apr 28 03:00:00 1957 EDT isdst=1 gmtoff=-14400
    #America/New_York  Sun Oct 27 05:59:59 1957 UTC = Sun Oct 27 01:59:59 1957 EDT isdst=1 gmtoff=-14400
    #America/New_York  Sun Oct 27 06:00:00 1957 UTC = Sun Oct 27 01:00:00 1957 EST isdst=0 gmtoff=-18000
    
    tz = Timezone.get('America/New_York')
    assert_equal(DateTime.new(1957,4,28,1,59,59), tz.utc_to_local(DateTime.new(1957,4,28,6,59,59)))
    assert_equal(DateTime.new(1957,4,28,3,0,0), tz.utc_to_local(DateTime.new(1957,4,28,7,0,0)))    
    assert_equal(DateTime.new(1957,10,27,1,59,59), tz.utc_to_local(DateTime.new(1957,10,27,5,59,59)))
    assert_equal(DateTime.new(1957,10,27,1,0,0), tz.utc_to_local(DateTime.new(1957,10,27,6,0,0)))
    
    assert_equal(DateTime.new(1957,4,28,6,59,59), tz.local_to_utc(DateTime.new(1957,4,28,1,59,59)))
    assert_equal(DateTime.new(1957,4,28,7,0,0), tz.local_to_utc(DateTime.new(1957,4,28,3,0,0)))
    assert_equal(DateTime.new(1957,10,27,5,59,59), tz.local_to_utc(DateTime.new(1957,10,27,1,59,59), true))
    assert_equal(DateTime.new(1957,10,27,6,59,59), tz.local_to_utc(DateTime.new(1957,10,27,1,59,59), false))
    assert_equal(DateTime.new(1957,10,27,5,0,0), tz.local_to_utc(DateTime.new(1957,10,27,1,0,0), true))
    assert_equal(DateTime.new(1957,10,27,6,0,0), tz.local_to_utc(DateTime.new(1957,10,27,1,0,0), false))
    
    assert_raises(PeriodNotFound) { tz.local_to_utc(DateTime.new(1957,4,28,2,0,0)) }
    assert_raises(AmbiguousTime) { tz.local_to_utc(DateTime.new(1957,10,27,1,0,0)) }
    
    assert_equal(:EST, tz.period_for_utc(DateTime.new(1957,4,28,6,59,59)).zone_identifier)
    assert_equal(:EDT, tz.period_for_utc(DateTime.new(1957,4,28,7,0,0)).zone_identifier)
    assert_equal(:EDT, tz.period_for_utc(DateTime.new(1957,10,27,5,59,59)).zone_identifier)
    assert_equal(:EST, tz.period_for_utc(DateTime.new(1957,10,27,6,0,0)).zone_identifier)
    
    assert_equal(:EST, tz.period_for_local(DateTime.new(1957,4,28,1,59,59)).zone_identifier)
    assert_equal(:EDT, tz.period_for_local(DateTime.new(1957,4,28,3,0,0)).zone_identifier)
    assert_equal(:EDT, tz.period_for_local(DateTime.new(1957,10,27,1,59,59), true).zone_identifier)
    assert_equal(:EST, tz.period_for_local(DateTime.new(1957,10,27,1,59,59), false).zone_identifier)
    assert_equal(:EDT, tz.period_for_local(DateTime.new(1957,10,27,1,0,0), true).zone_identifier)
    assert_equal(:EST, tz.period_for_local(DateTime.new(1957,10,27,1,0,0), false).zone_identifier)
    
    assert_equal(-18000, tz.period_for_utc(DateTime.new(1957,4,28,6,59,59)).utc_total_offset)
    assert_equal(-14400, tz.period_for_utc(DateTime.new(1957,4,28,7,0,0)).utc_total_offset)
    assert_equal(-14400, tz.period_for_utc(DateTime.new(1957,10,27,5,59,59)).utc_total_offset)
    assert_equal(-18000, tz.period_for_utc(DateTime.new(1957,10,27,6,0,0)).utc_total_offset)
    
    assert_equal(-18000, tz.period_for_local(DateTime.new(1957,4,28,1,59,59)).utc_total_offset)
    assert_equal(-14400, tz.period_for_local(DateTime.new(1957,4,28,3,0,0)).utc_total_offset)
    assert_equal(-14400, tz.period_for_local(DateTime.new(1957,10,27,1,59,59), true).utc_total_offset)
    assert_equal(-18000, tz.period_for_local(DateTime.new(1957,10,27,1,59,59), false).utc_total_offset)
    assert_equal(-14400, tz.period_for_local(DateTime.new(1957,10,27,1,0,0), true).utc_total_offset)
    assert_equal(-18000, tz.period_for_local(DateTime.new(1957,10,27,1,0,0), false).utc_total_offset)
  end
  
  def test_time_boundary
    #America/New_York  Sun Oct 26 06:00:00 1969 UTC = Sun Oct 26 01:00:00 1969 EST isdst=0 gmtoff=-18000
    #America/New_York  Sun Apr 26 06:59:59 1970 UTC = Sun Apr 26 01:59:59 1970 EST isdst=0 gmtoff=-18000
    
    tz = Timezone.get('America/New_York')    
    assert_equal(DateTime.new(1970,1,1,0,0,0), tz.utc_to_local(DateTime.new(1970,1,1,5,0,0)))
    assert_equal(DateTime.new(1970,1,1,5,0,0), tz.local_to_utc(DateTime.new(1970,1,1,0,0,0)))
    assert_equal(Time.utc(1970,1,1,0,0,0), tz.utc_to_local(Time.utc(1970,1,1,5,0,0)))
    assert_equal(Time.utc(1970,1,1,5,0,0), tz.local_to_utc(Time.utc(1970,1,1,0,0,0)))
    assert_equal(0, tz.utc_to_local(18000))
    assert_equal(18000, tz.local_to_utc(0))
  end
end