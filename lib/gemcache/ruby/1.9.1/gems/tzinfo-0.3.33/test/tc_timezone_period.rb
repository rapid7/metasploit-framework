$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'test/unit'
require 'tzinfo'

include TZInfo

class TCTimezonePeriod < Test::Unit::TestCase
  
  def test_initialize_start_end
    std = TimezoneOffsetInfo.new(-7200, 0, :TEST)
    dst = TimezoneOffsetInfo.new(-7200, 3600, :TEST)
    start_t = TimezoneTransitionInfo.new(dst, std, 1136073600)
    end_t = TimezoneTransitionInfo.new(std, dst, 1136160000)
      
    p = TimezonePeriod.new(start_t, end_t)
    
    assert_equal(start_t, p.start_transition)
    assert_equal(end_t, p.end_transition)
    assert_equal(dst, p.offset)
    assert_equal(DateTime.new(2006,1,1,0,0,0), p.utc_start)
    assert_equal(DateTime.new(2006,1,2,0,0,0), p.utc_end)
    assert_equal(-7200, p.utc_offset)
    assert_equal(3600, p.std_offset)
    assert_equal(-3600, p.utc_total_offset)
    assert_equal(Rational(-3600, 86400), p.utc_total_offset_rational)
    assert_equal(:TEST, p.zone_identifier)
    assert_equal(:TEST, p.abbreviation)    
    assert_equal(DateTime.new(2005,12,31,23,0,0), p.local_start)    
    assert_equal(DateTime.new(2006,1,1,23,0,0), p.local_end)
  end
  
  def test_initialize_start_end_offset
    std = TimezoneOffsetInfo.new(-7200, 0, :TEST)
    dst = TimezoneOffsetInfo.new(-7200, 3600, :TEST)
    special = TimezoneOffsetInfo.new(0, 0, :SPECIAL)
    start_t = TimezoneTransitionInfo.new(dst, std, 1136073600)
    end_t = TimezoneTransitionInfo.new(std, dst, 1136160000)
      
    assert_raises(ArgumentError) { TimezonePeriod.new(start_t, end_t, special) }
  end
  
  def test_initialize_start
    std = TimezoneOffsetInfo.new(-7200, 0, :TEST)
    dst = TimezoneOffsetInfo.new(-7200, 3600, :TEST)
    start_t = TimezoneTransitionInfo.new(dst, std, 1136073600)   
      
    p = TimezonePeriod.new(start_t, nil)
    
    assert_equal(start_t, p.start_transition)
    assert_nil(p.end_transition)
    assert_equal(dst, p.offset)
    assert_equal(DateTime.new(2006,1,1,0,0,0), p.utc_start)
    assert_nil(p.utc_end)
    assert_equal(-7200, p.utc_offset)
    assert_equal(3600, p.std_offset)
    assert_equal(-3600, p.utc_total_offset)
    assert_equal(Rational(-3600, 86400), p.utc_total_offset_rational)
    assert_equal(:TEST, p.zone_identifier)
    assert_equal(:TEST, p.abbreviation)    
    assert_equal(DateTime.new(2005,12,31,23,0,0), p.local_start)    
    assert_nil(p.local_end)
  end
  
  def test_initialize_start_offset
    std = TimezoneOffsetInfo.new(-7200, 0, :TEST)
    dst = TimezoneOffsetInfo.new(-7200, 3600, :TEST)
    special = TimezoneOffsetInfo.new(0, 0, :SPECIAL)
    start_t = TimezoneTransitionInfo.new(dst, std, 1136073600)   
      
    assert_raises(ArgumentError) { TimezonePeriod.new(start_t, nil, special) }
  end
  
  def test_initialize_end
    std = TimezoneOffsetInfo.new(-7200, 0, :TEST)
    dst = TimezoneOffsetInfo.new(-7200, 3600, :TEST)    
    end_t = TimezoneTransitionInfo.new(std, dst, 1136160000)
      
    p = TimezonePeriod.new(nil, end_t)
    
    assert_nil(p.start_transition)
    assert_equal(end_t, p.end_transition)
    assert_equal(dst, p.offset)
    assert_nil(p.utc_start)
    assert_equal(DateTime.new(2006,1,2,0,0,0), p.utc_end)
    assert_equal(-7200, p.utc_offset)
    assert_equal(3600, p.std_offset)
    assert_equal(-3600, p.utc_total_offset)
    assert_equal(Rational(-3600, 86400), p.utc_total_offset_rational)
    assert_equal(:TEST, p.zone_identifier)
    assert_equal(:TEST, p.abbreviation)    
    assert_nil(p.local_start)    
    assert_equal(DateTime.new(2006,1,1,23,0,0), p.local_end)
  end
  
  def test_initialize_end_offset
    std = TimezoneOffsetInfo.new(-7200, 0, :TEST)
    dst = TimezoneOffsetInfo.new(-7200, 3600, :TEST)    
    special = TimezoneOffsetInfo.new(0, 0, :SPECIAL)
    end_t = TimezoneTransitionInfo.new(std, dst, 1136160000)
      
    assert_raises(ArgumentError) { TimezonePeriod.new(nil, end_t, special) }    
  end
  
  def test_initialize
    assert_raises(ArgumentError) { TimezonePeriod.new(nil, nil) }
  end
  
  def test_initialize_offset
    special = TimezoneOffsetInfo.new(0, 0, :SPECIAL)
      
    p = TimezonePeriod.new(nil, nil, special)
    
    assert_nil(p.start_transition)
    assert_nil(p.end_transition)
    assert_equal(special, p.offset)
    assert_nil(p.utc_start)
    assert_nil(p.utc_end)
    assert_equal(0, p.utc_offset)
    assert_equal(0, p.std_offset)
    assert_equal(0, p.utc_total_offset)
    assert_equal(Rational(0, 86400), p.utc_total_offset_rational)
    assert_equal(:SPECIAL, p.zone_identifier)
    assert_equal(:SPECIAL, p.abbreviation)    
    assert_nil(p.local_start)    
    assert_nil(p.local_end)  
  end
  
  def test_dst    
    p1 = TimezonePeriod.new(nil, nil, TimezoneOffsetInfo.new(-14400, 3600, :TEST))
    p2 = TimezonePeriod.new(nil, nil, TimezoneOffsetInfo.new(-14400, 0, :TEST))
    p3 = TimezonePeriod.new(nil, nil, TimezoneOffsetInfo.new(-14400, -3600, :TEST))
    p4 = TimezonePeriod.new(nil, nil, TimezoneOffsetInfo.new(-14400, 7200, :TEST))
    p5 = TimezonePeriod.new(nil, nil, TimezoneOffsetInfo.new(-14400, -7200, :TEST))
    
    assert_equal(true, p1.dst?)
    assert_equal(false, p2.dst?)
    assert_equal(true, p3.dst?)
    assert_equal(true, p4.dst?)
    assert_equal(true, p5.dst?)
  end
  
  def test_valid_for_utc
    offset = TimezoneOffsetInfo.new(-7200, 3600, :TEST)
    t1 = TimezoneTransitionInfo.new(offset, offset, 1104541261)
    t2 = TimezoneTransitionInfo.new(offset, offset, 1107309722)
    t3 = TimezoneTransitionInfo.new(offset, offset, 210551144461, 86400)
    t4 = TimezoneTransitionInfo.new(offset, offset, 105276956461, 43200)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(nil, t2)
    p3 = TimezonePeriod.new(t1, nil)
    p4 = TimezonePeriod.new(nil, nil, offset)
    p5 = TimezonePeriod.new(t3, t4)
    
    assert_equal(true, p1.valid_for_utc?(DateTime.new(2005,1,1,1,1,1)))
    assert_equal(true, p1.valid_for_utc?(Time.utc(2005,2,2,2,2,1)))
    assert_equal(true, p1.valid_for_utc?(1104541262))
    assert_equal(true, p1.valid_for_utc?(DateTime.new(2005,2,2,2,2,0)))
    assert_equal(false, p1.valid_for_utc?(DateTime.new(2005,1,1,1,1,0)))
    assert_equal(false, p1.valid_for_utc?(DateTime.new(2005,2,2,2,2,3)))
    assert_equal(false, p1.valid_for_utc?(DateTime.new(1960,1,1,1,1,0)))
    assert_equal(false, p1.valid_for_utc?(DateTime.new(2040,1,1,1,1,0)))
    
    assert_equal(true, p2.valid_for_utc?(DateTime.new(2005,1,1,1,1,1)))
    assert_equal(true, p2.valid_for_utc?(Time.utc(2005,2,2,2,2,1)))
    assert_equal(true, p2.valid_for_utc?(1104541262))
    assert_equal(true, p2.valid_for_utc?(DateTime.new(2005,2,2,2,2,0)))
    assert_equal(true, p2.valid_for_utc?(DateTime.new(2005,1,1,1,1,0)))    
    assert_equal(false, p2.valid_for_utc?(DateTime.new(2005,2,2,2,2,3)))
    assert_equal(true, p2.valid_for_utc?(DateTime.new(1960,1,1,1,1,0)))
    assert_equal(false, p2.valid_for_utc?(DateTime.new(2040,1,1,1,1,0)))
    
    assert_equal(true, p3.valid_for_utc?(DateTime.new(2005,1,1,1,1,1)))
    assert_equal(true, p3.valid_for_utc?(Time.utc(2005,2,2,2,2,1)))
    assert_equal(true, p3.valid_for_utc?(1104541262))
    assert_equal(true, p3.valid_for_utc?(DateTime.new(2005,2,2,2,2,0)))
    assert_equal(false, p3.valid_for_utc?(DateTime.new(2005,1,1,1,1,0)))
    assert_equal(true, p3.valid_for_utc?(DateTime.new(2005,2,2,2,2,3)))
    assert_equal(false, p3.valid_for_utc?(DateTime.new(1960,1,1,1,1,0)))
    assert_equal(true, p3.valid_for_utc?(DateTime.new(2040,1,1,1,1,0)))
    
    assert_equal(true, p4.valid_for_utc?(DateTime.new(2005,1,1,1,1,1)))
    assert_equal(true, p4.valid_for_utc?(Time.utc(2005,2,2,2,2,1)))
    assert_equal(true, p4.valid_for_utc?(1104541262))
    assert_equal(true, p4.valid_for_utc?(DateTime.new(2005,2,2,2,2,0)))
    assert_equal(true, p4.valid_for_utc?(DateTime.new(2005,1,1,1,1,0)))
    assert_equal(true, p4.valid_for_utc?(DateTime.new(2005,2,2,2,2,3)))
    assert_equal(true, p4.valid_for_utc?(DateTime.new(1960,1,1,1,1,0)))
    assert_equal(true, p4.valid_for_utc?(DateTime.new(2040,1,1,1,1,0)))
    
    assert_equal(false, p5.valid_for_utc?(Time.utc(2005,1,1,1,1,1)))
    assert_equal(false, p5.valid_for_utc?(1104541262))
  end
  
  def test_utc_after_start
    offset = TimezoneOffsetInfo.new(-7200, 3600, :TEST)
    t1 = TimezoneTransitionInfo.new(offset, offset, 1104541261)
    t2 = TimezoneTransitionInfo.new(offset, offset, 1107309722)
    t3 = TimezoneTransitionInfo.new(offset, offset, 210077845261, 86400)
    t4 = TimezoneTransitionInfo.new(offset, offset, 105040306861, 43200)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(nil, t2)
    p3 = TimezonePeriod.new(t3, t4)

    assert_equal(true, p1.utc_after_start?(DateTime.new(2005,1,1,1,1,1)))    
    assert_equal(true, p1.utc_after_start?(Time.utc(2005,1,1,1,1,2)))
    assert_equal(false, p1.utc_after_start?(1104541260))
    assert_equal(true, p1.utc_after_start?(DateTime.new(2045,1,1,1,1,0)))
    assert_equal(false, p1.utc_after_start?(DateTime.new(1955,1,1,1,1,0)))

    assert_equal(true, p2.utc_after_start?(DateTime.new(2005,1,1,1,1,1)))    
    assert_equal(true, p2.utc_after_start?(Time.utc(2005,1,1,1,1,2)))
    assert_equal(true, p2.utc_after_start?(1104541260)) 
    
    assert_equal(true, p3.utc_after_start?(Time.utc(2005,1,2,1,1,1)))
    assert_equal(true, p3.utc_after_start?(1104627661))
  end
  
  def test_utc_before_end
    offset = TimezoneOffsetInfo.new(-7200, 3600, :TEST)
    t1 = TimezoneTransitionInfo.new(offset, offset, 1104541261)
    t2 = TimezoneTransitionInfo.new(offset, offset, 1107309722)
    t3 = TimezoneTransitionInfo.new(offset, offset, 210077845261, 86400)
    t4 = TimezoneTransitionInfo.new(offset, offset, 105040306861, 43200)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(t1, nil)
    p3 = TimezonePeriod.new(t3, t4)
    
    assert_equal(true, p1.utc_before_end?(DateTime.new(2005,2,2,2,2,1)))    
    assert_equal(true, p1.utc_before_end?(Time.utc(2005,2,2,2,2,0)))   
    assert_equal(false, p1.utc_before_end?(1107309723))
    assert_equal(false, p1.utc_before_end?(DateTime.new(2045,1,1,1,1,0)))
    assert_equal(true, p1.utc_before_end?(DateTime.new(1955,1,1,1,1,0)))
    
    assert_equal(true, p2.utc_before_end?(DateTime.new(2005,2,2,2,2,1)))    
    assert_equal(true, p2.utc_before_end?(Time.utc(2005,2,2,2,2,0)))   
    assert_equal(true, p2.utc_before_end?(1107309723))
    
    assert_equal(false, p3.utc_before_end?(Time.utc(2005,1,2,1,1,1)))
    assert_equal(false, p3.utc_before_end?(1104627661))
  end
  
  def test_valid_for_local
    offset = TimezoneOffsetInfo.new(-7200, 3600, :TEST)
    t1 = TimezoneTransitionInfo.new(offset, offset, 1104544861)
    t2 = TimezoneTransitionInfo.new(offset, offset, 1107313322)
    t3 = TimezoneTransitionInfo.new(offset, offset, 1104544861)
    t4 = TimezoneTransitionInfo.new(offset, offset, 210551144461, 86400)
    t5 = TimezoneTransitionInfo.new(offset, offset, 105276956461, 43200)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(nil, t2)
    p3 = TimezonePeriod.new(t3, nil)
    p4 = TimezonePeriod.new(nil, nil, offset)
    p5 = TimezonePeriod.new(t4, t5)
    
    assert_equal(true, p1.valid_for_local?(DateTime.new(2005,1,1,1,1,1)))
    assert_equal(true, p1.valid_for_local?(Time.utc(2005,2,2,2,2,1)))
    assert_equal(true, p1.valid_for_local?(1104541262))
    assert_equal(true, p1.valid_for_local?(DateTime.new(2005,2,2,2,2,0)))
    assert_equal(false, p1.valid_for_local?(DateTime.new(2005,1,1,1,1,0)))
    assert_equal(false, p1.valid_for_local?(DateTime.new(2005,2,2,2,2,3)))
    assert_equal(false, p1.valid_for_local?(DateTime.new(1960,1,1,1,1,0)))
    assert_equal(false, p1.valid_for_local?(DateTime.new(2040,1,1,1,1,0)))
    
    assert_equal(true, p2.valid_for_local?(DateTime.new(2005,1,1,1,1,1)))
    assert_equal(true, p2.valid_for_local?(DateTime.new(2005,2,2,2,2,1)))
    assert_equal(true, p2.valid_for_local?(1104541262))
    assert_equal(true, p2.valid_for_local?(DateTime.new(2005,2,2,2,2,0)))
    assert_equal(true, p2.valid_for_local?(DateTime.new(2005,1,1,1,1,0)))
    assert_equal(false, p2.valid_for_local?(DateTime.new(2005,2,2,2,2,3)))
    assert_equal(true, p2.valid_for_local?(DateTime.new(1960,1,1,1,1,0)))
    assert_equal(false, p2.valid_for_local?(DateTime.new(2040,1,1,1,1,0)))
    
    assert_equal(true, p3.valid_for_local?(DateTime.new(2005,1,1,1,1,1)))
    assert_equal(true, p3.valid_for_local?(DateTime.new(2005,2,2,2,2,1)))
    assert_equal(true, p3.valid_for_local?(1104541262))
    assert_equal(true, p3.valid_for_local?(DateTime.new(2005,2,2,2,2,0)))
    assert_equal(false, p3.valid_for_local?(DateTime.new(2005,1,1,1,1,0)))
    assert_equal(true, p3.valid_for_local?(DateTime.new(2005,2,2,2,2,3)))
    assert_equal(false, p3.valid_for_local?(DateTime.new(1960,1,1,1,1,0)))
    assert_equal(true, p3.valid_for_local?(DateTime.new(2040,1,1,1,1,0)))
    
    assert_equal(true, p4.valid_for_local?(DateTime.new(2005,1,1,1,1,1)))
    assert_equal(true, p4.valid_for_local?(DateTime.new(2005,2,2,2,2,1)))
    assert_equal(true, p4.valid_for_local?(1104541262))
    assert_equal(true, p4.valid_for_local?(DateTime.new(2005,2,2,2,2,0)))
    assert_equal(true, p4.valid_for_local?(DateTime.new(2005,1,1,1,1,0)))
    assert_equal(true, p4.valid_for_local?(DateTime.new(2005,2,2,2,2,3)))
    assert_equal(true, p4.valid_for_local?(DateTime.new(1960,1,1,1,1,0)))
    assert_equal(true, p4.valid_for_local?(DateTime.new(2040,1,1,1,1,0)))
    
    assert_equal(false, p5.valid_for_utc?(Time.utc(2005,1,1,1,1,1)))
    assert_equal(false, p5.valid_for_utc?(1104541262))
  end
  
  def test_local_after_start
    offset = TimezoneOffsetInfo.new(-7200, 3600, :TEST)
    t1 = TimezoneTransitionInfo.new(offset, offset, 1104544861)
    t2 = TimezoneTransitionInfo.new(offset, offset, 1107313322)
    t3 = TimezoneTransitionInfo.new(offset, offset, 210077845261, 86400)
    t4 = TimezoneTransitionInfo.new(offset, offset, 105040306861, 43200)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(nil, t2)
    p3 = TimezonePeriod.new(t3, t4)

    assert_equal(true, p1.local_after_start?(DateTime.new(2005,1,1,1,1,1)))    
    assert_equal(true, p1.local_after_start?(Time.utc(2005,1,1,1,1,2)))
    assert_equal(false, p1.local_after_start?(1104541260))
    assert_equal(true, p1.local_after_start?(DateTime.new(2045,1,1,1,1,0)))
    assert_equal(false, p1.local_after_start?(DateTime.new(1955,1,1,1,1,0)))

    assert_equal(true, p2.local_after_start?(DateTime.new(2005,1,1,1,1,1)))    
    assert_equal(true, p2.local_after_start?(Time.utc(2005,1,1,1,1,2)))
    assert_equal(true, p2.local_after_start?(1104541260))    
    
    assert_equal(true, p3.local_after_start?(Time.utc(2005,1,2,1,1,1)))
    assert_equal(true, p3.local_after_start?(1104627661))
  end
  
  def test_local_before_end
    offset = TimezoneOffsetInfo.new(-7200, 3600, :TEST)
    t1 = TimezoneTransitionInfo.new(offset, offset, 1104544861)
    t2 = TimezoneTransitionInfo.new(offset, offset, 1107313322)
    t3 = TimezoneTransitionInfo.new(offset, offset, 210077845261, 86400)
    t4 = TimezoneTransitionInfo.new(offset, offset, 105040306861, 43200)
    
    p1 = TimezonePeriod.new(t1, t2)    
    p2 = TimezonePeriod.new(t1, nil)
    p3 = TimezonePeriod.new(t3, t4)    
        
    assert_equal(true, p1.local_before_end?(DateTime.new(2005,2,2,2,2,1)))    
    assert_equal(true, p1.local_before_end?(Time.utc(2005,2,2,2,2,0)))   
    assert_equal(false, p1.local_before_end?(1107309723))
    assert_equal(false, p1.local_before_end?(DateTime.new(2045,1,1,1,1,0)))
    assert_equal(true, p1.local_before_end?(DateTime.new(1955,1,1,1,1,0)))
    
    assert_equal(true, p2.local_before_end?(DateTime.new(2005,2,2,2,2,1)))    
    assert_equal(true, p2.local_before_end?(Time.utc(2005,2,2,2,2,0)))   
    assert_equal(true, p2.local_before_end?(1107309723))
    
    assert_equal(false, p3.local_before_end?(Time.utc(2005,1,2,1,1,1)))
    assert_equal(false, p3.local_before_end?(1104627661))
  end
  
  def test_to_local
    p1 = TimezonePeriod.new(nil, nil, TimezoneOffsetInfo.new(-14400, 3600, :TEST))
    p2 = TimezonePeriod.new(nil, nil, TimezoneOffsetInfo.new(-14400, 0, :TEST))
    p3 = TimezonePeriod.new(nil, nil, TimezoneOffsetInfo.new(7200, 3600, :TEST))
        
    assert_equal(DateTime.new(2005,1,19,22,0,0), p1.to_local(DateTime.new(2005,1,20,1,0,0)))
    assert_equal(Time.utc(2005,1,19,21,0,0), p2.to_local(Time.utc(2005,1,20,1,0,0)))
    assert_equal(1106193600, p3.to_local(1106182800))
  end
  
  def test_to_utc
    p1 = TimezonePeriod.new(nil, nil, TimezoneOffsetInfo.new(-14400, 3600, :TEST))
    p2 = TimezonePeriod.new(nil, nil, TimezoneOffsetInfo.new(-14400, 0, :TEST))
    p3 = TimezonePeriod.new(nil, nil, TimezoneOffsetInfo.new(7200, 3600, :TEST))
        
    assert_equal(DateTime.new(2005,1,20,4,0,0), p1.to_utc(DateTime.new(2005,1,20,1,0,0)))
    assert_equal(Time.utc(2005,1,20,5,0,0), p2.to_utc(Time.utc(2005,1,20,1,0,0)))
    assert_equal(1106172000, p3.to_utc(1106182800))
  end
  
  def test_time_boundary_start
    o1 = TimezoneOffsetInfo.new(-3600, 0, :TEST)
    o2 = TimezoneOffsetInfo.new(-3600, 3600, :TEST)
    t1 = TimezoneTransitionInfo.new(o1, o2, 0)
    
    p1 = TimezonePeriod.new(t1, nil)
    
    assert_equal(DateTime.new(1969,12,31,23,0,0), p1.local_start)    
  end
  
  def test_time_boundary_end
    o1 = TimezoneOffsetInfo.new(0, 3600, :TEST)
    o2 = TimezoneOffsetInfo.new(0, 0, :TEST)
    t1 = TimezoneTransitionInfo.new(o2, o1, 2147482800)
    
    p1 = TimezonePeriod.new(nil, t1)
    
    assert_equal(DateTime.new(2038,1,19,4,0,0), p1.local_end)
  end
  
  def test_equality
    o1 = TimezoneOffsetInfo.new(0, 3600, :TEST)
    o2 = TimezoneOffsetInfo.new(0, 0, :TEST)
    t1 = TimezoneTransitionInfo.new(o1, o2, 1149368400)    
    t2 = TimezoneTransitionInfo.new(o1, o2, 19631123, 8)
    t3 = TimezoneTransitionInfo.new(o1, o2, 1149454800)
    t4 = TimezoneTransitionInfo.new(o1, o2, 1149541200)
    
    p1 = TimezonePeriod.new(t1, t3)
    p2 = TimezonePeriod.new(t1, t3)
    p3 = TimezonePeriod.new(t2, t3)
    p4 = TimezonePeriod.new(t3, nil)
    p5 = TimezonePeriod.new(t3, nil)
    p6 = TimezonePeriod.new(t4, nil)
    p7 = TimezonePeriod.new(nil, t3)
    p8 = TimezonePeriod.new(nil, t3)
    p9 = TimezonePeriod.new(nil, t4)
    p10 = TimezonePeriod.new(nil, nil, o1)
    p11 = TimezonePeriod.new(nil, nil, o1)
    p12 = TimezonePeriod.new(nil, nil, o2)
    
    assert_equal(true, p1 == p1)
    assert_equal(true, p1 == p2)
    assert_equal(true, p1 == p3)
    assert_equal(false, p1 == p4)
    assert_equal(false, p1 == p5)
    assert_equal(false, p1 == p6)
    assert_equal(false, p1 == p7)
    assert_equal(false, p1 == p8)
    assert_equal(false, p1 == p9)
    assert_equal(false, p1 == p10)
    assert_equal(false, p1 == p11)
    assert_equal(false, p1 == p12)
    assert_equal(false, p1 == Object.new)
    
    assert_equal(true, p4 == p4)
    assert_equal(true, p4 == p5)
    assert_equal(false, p4 == p6)
    assert_equal(false, p4 == Object.new)
    
    assert_equal(true, p7 == p7)
    assert_equal(true, p7 == p8)
    assert_equal(false, p7 == p9)
    assert_equal(false, p7 == Object.new)
    
    assert_equal(true, p10 == p10)
    assert_equal(true, p10 == p11)
    assert_equal(false, p10 == p12)
    assert_equal(false, p10 == Object.new)
  end
  
  def test_eql
    o1 = TimezoneOffsetInfo.new(0, 3600, :TEST)
    o2 = TimezoneOffsetInfo.new(0, 0, :TEST)
    t1 = TimezoneTransitionInfo.new(o1, o2, 1149368400)    
    t2 = TimezoneTransitionInfo.new(o1, o2, 19631123, 8)
    t3 = TimezoneTransitionInfo.new(o1, o2, 1149454800)
    t4 = TimezoneTransitionInfo.new(o1, o2, 1149541200)
    
    p1 = TimezonePeriod.new(t1, t3)
    p2 = TimezonePeriod.new(t1, t3)
    p3 = TimezonePeriod.new(t2, t3)
    p4 = TimezonePeriod.new(t3, nil)
    p5 = TimezonePeriod.new(t3, nil)
    p6 = TimezonePeriod.new(t4, nil)
    p7 = TimezonePeriod.new(nil, t3)
    p8 = TimezonePeriod.new(nil, t3)
    p9 = TimezonePeriod.new(nil, t4)
    p10 = TimezonePeriod.new(nil, nil, o1)
    p11 = TimezonePeriod.new(nil, nil, o1)
    p12 = TimezonePeriod.new(nil, nil, o2)
    
    assert_equal(true, p1.eql?(p1))
    assert_equal(true, p1.eql?(p2))
    assert_equal(false, p1.eql?(p3))
    assert_equal(false, p1.eql?(p4))
    assert_equal(false, p1.eql?(p5))
    assert_equal(false, p1.eql?(p6))
    assert_equal(false, p1.eql?(p7))
    assert_equal(false, p1.eql?(p8))
    assert_equal(false, p1.eql?(p9))
    assert_equal(false, p1.eql?(p10))
    assert_equal(false, p1.eql?(p11))
    assert_equal(false, p1.eql?(p12))
    assert_equal(false, p1.eql?(Object.new))
    
    assert_equal(true, p4.eql?(p4))
    assert_equal(true, p4.eql?(p5))
    assert_equal(false, p4.eql?(p6))
    assert_equal(false, p4.eql?(Object.new))
    
    assert_equal(true, p7.eql?(p7))
    assert_equal(true, p7.eql?(p8))
    assert_equal(false, p7.eql?(p9))
    assert_equal(false, p7.eql?(Object.new))
    
    assert_equal(true, p10.eql?(p10))
    assert_equal(true, p10.eql?(p11))
    assert_equal(false, p10.eql?(p12))
    assert_equal(false, p10.eql?(Object.new))
  end
  
  def test_hash
    o1 = TimezoneOffsetInfo.new(0, 3600, :TEST)
    o2 = TimezoneOffsetInfo.new(0, 0, :TEST)
    t1 = TimezoneTransitionInfo.new(o1, o2, 1149368400)    
    t2 = TimezoneTransitionInfo.new(o1, o2, 19631123, 8)
    t3 = TimezoneTransitionInfo.new(o1, o2, 1149454800)
    t4 = TimezoneTransitionInfo.new(o1, o2, 1149541200)
    
    p1 = TimezonePeriod.new(t1, t3)    
    p2 = TimezonePeriod.new(t3, nil)
    p3 = TimezonePeriod.new(nil, t3)
    p4 = TimezonePeriod.new(nil, nil, o1)

    assert_equal(t1.hash ^ t3.hash, p1.hash)
    assert_equal(t3.hash ^ nil.hash, p2.hash)
    assert_equal(nil.hash ^ t3.hash, p3.hash)
    assert_equal(nil.hash ^ nil.hash ^ o1.hash, p4.hash)    
  end
end