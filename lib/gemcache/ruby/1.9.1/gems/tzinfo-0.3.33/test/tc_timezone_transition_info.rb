$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'date'
require 'test/unit'
require 'tzinfo'

include TZInfo

class TCTimezoneTransitionInfo < Test::Unit::TestCase
  
  def test_offset
    t = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 1148949080)
    
    assert_equal(TimezoneOffsetInfo.new(3600, 3600, :TDT), t.offset)
  end
  
  def test_previous_offset
    t = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 1148949080)
    
    assert_equal(TimezoneOffsetInfo.new(3600, 0, :TST), t.previous_offset)
  end
  
  def test_at
    t1 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 1148949080)
    t2 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 5300392727, 2160)
      
    assert(TimeOrDateTime.new(1148949080).eql?(t1.at))
    assert(TimeOrDateTime.new(DateTime.new(2006, 5, 30, 0, 31, 20)).eql?(t2.at))
  end
  
  def test_local_end
    t1 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 1148949080)
    t2 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 5300392727, 2160)
      
    assert(TimeOrDateTime.new(1148952680).eql?(t1.local_end))
    assert(TimeOrDateTime.new(DateTime.new(2006, 5, 30, 1, 31, 20)).eql?(t2.local_end))
  end
  
  def test_local_start
    t1 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 1148949080)
    t2 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 5300392727, 2160)
      
    assert(TimeOrDateTime.new(1148956280).eql?(t1.local_start))
    assert(TimeOrDateTime.new(DateTime.new(2006, 5, 30, 2, 31, 20)).eql?(t2.local_start))
  end
  
  def test_local_end_before_epoch
    t = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(-7200, 3600, :TDT),
      TimezoneOffsetInfo.new(-7200, 0, :TST), 1800)
      
    assert(TimeOrDateTime.new(DateTime.new(1969, 12, 31, 22, 30, 0)).eql?(t.local_end))
  end
  
  def test_local_start_before_epoch
    t = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(-7200, 3600, :TDT),
      TimezoneOffsetInfo.new(-7200, 0, :TST), 1800)
      
    assert(TimeOrDateTime.new(DateTime.new(1969, 12, 31, 23, 30, 0)).eql?(t.local_start))
  end
  
  def test_local_end_after_32bit
    t = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 2147482800)
      
    assert(TimeOrDateTime.new(DateTime.new(2038, 1, 19, 4, 0, 0)).eql?(t.local_end))
  end
  
  def test_local_start_after_32bit
    t = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 2147482800)
      
    assert(TimeOrDateTime.new(DateTime.new(2038, 1, 19, 5, 0, 0)).eql?(t.local_start))
  end
  
  def test_equality_timestamp
    t1 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 1148949080)
    t2 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 1148949080)
    t3 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 5300392727, 2160)
    t4 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 1148949081)
    t5 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 7852433803, 3200)
    t6 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3601, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 1148949080) 
    t7 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3601, 0, :TST), 1148949080)
      
    assert_equal(true, t1 == t1)
    assert_equal(true, t1 == t2)
    assert_equal(true, t1 == t3)
    assert_equal(false, t1 == t4)
    assert_equal(false, t1 == t5)
    assert_equal(false, t1 == t6)
    assert_equal(false, t1 == t7)
    assert_equal(false, t1 == Object.new)
  end
  
  def test_equality_datetime
    t1 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 5300392727, 2160)
    t2 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 5300392727, 2160)
    t3 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 1148949080)
    t4 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 7852433803, 3200)
    t5 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 1148949081)
    t6 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3601, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 5300392727, 2160) 
    t7 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3601, 0, :TST), 5300392727, 2160)
      
    assert_equal(true, t1 == t1)
    assert_equal(true, t1 == t2)
    assert_equal(true, t1 == t3)
    assert_equal(false, t1 == t4)
    assert_equal(false, t1 == t5)
    assert_equal(false, t1 == t6)
    assert_equal(false, t1 == t7)
    assert_equal(false, t1 == Object.new)
  end
  
  def test_eql_timestamp
    t1 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 1148949080)
    t2 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 1148949080)
    t3 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 5300392727, 2160)
    t4 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 1148949081)
    t5 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3601, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 1148949080) 
    t6 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3601, 0, :TST), 1148949080)
      
    assert_equal(true, t1.eql?(t1))
    assert_equal(true, t1.eql?(t2))
    assert_equal(false, t1.eql?(t3))
    assert_equal(false, t1.eql?(t4))
    assert_equal(false, t1.eql?(t5))
    assert_equal(false, t1.eql?(t6))    
    assert_equal(false, t1.eql?(Object.new))
  end
  
  def test_eql_datetime
    t1 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 5300392727, 2160)
    t2 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 5300392727, 2160)
    t3 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 1148949080)
    t4 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 7852433803, 3200)
    t5 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3601, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 5300392727, 2160) 
    t6 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3601, 0, :TST), 5300392727, 2160)
      
    assert_equal(true, t1.eql?(t1))
    assert_equal(true, t1.eql?(t2))
    assert_equal(false, t1.eql?(t3))
    assert_equal(false, t1.eql?(t4))
    assert_equal(false, t1.eql?(t5))
    assert_equal(false, t1.eql?(t6))    
    assert_equal(false, t1.eql?(Object.new))
  end
  
  def test_hash
    t1 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 1148949080)
    t2 = TimezoneTransitionInfo.new(TimezoneOffsetInfo.new(3600, 3600, :TDT),
      TimezoneOffsetInfo.new(3600, 0, :TST), 5300392727, 2160)
      
    assert_equal(TimezoneOffsetInfo.new(3600, 3600, :TDT).hash ^
      TimezoneOffsetInfo.new(3600, 0, :TST).hash ^ 1148949080.hash ^ nil.hash, 
      t1.hash)
    assert_equal(TimezoneOffsetInfo.new(3600, 3600, :TDT).hash ^
      TimezoneOffsetInfo.new(3600, 0, :TST).hash ^ 5300392727.hash ^ 2160.hash, 
      t2.hash)
  end
    
end
