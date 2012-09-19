$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'test/unit'
require 'tzinfo'

include TZInfo

class TCDataTimezoneInfo < Test::Unit::TestCase
  
  def test_identifier
    dti = DataTimezoneInfo.new('Test/Zone')
    assert_equal('Test/Zone', dti.identifier)
  end

  def test_offset
    dti = DataTimezoneInfo.new('Test/Zone')
    
    # Test nothing raised
    dti.offset :o1, -18000, 3600, :TEST
  end
  
  def test_offset_already_defined
    dti = DataTimezoneInfo.new('Test/Zone')
    dti.offset :o1, 3600, 0, :TEST
    dti.offset :o2, 1800, 0, :TEST2
    
    assert_raises(ArgumentError) { dti.offset :o1, 3600, 3600, :TESTD }
  end
  
  def test_transition_time
    dti = DataTimezoneInfo.new('Test/Zone')
    dti.offset :o1, -18000, 3600, :TEST
    
    # Test nothing raised
    dti.transition 2006, 6, :o1, 1149368400
  end
  
  def test_transition_datetime
    dti = DataTimezoneInfo.new('Test/Zone')
    dti.offset :o1, -18000, 3600, :TEST
    
    # Test nothing raised
    dti.transition 2006, 6, :o1, 19631123, 8
  end
  
  def test_transition_invalid_offset
    dti = DataTimezoneInfo.new('Test/Zone')
    dti.offset :o1, -18000, 3600, :TEST
    
    dti.transition 2006, 6, :o1, 1149368400
    
    assert_raises(ArgumentError) { dti.transition 2006, 6, :o2, 1149454800 }    
  end
  
  def test_transition_no_offsets
    dti = DataTimezoneInfo.new('Test/Zone')
    
    assert_raises(ArgumentError) { dti.transition 2006, 6, :o1, 1149368400 }
  end
  
  def test_transition_invalid_order_month
    dti = DataTimezoneInfo.new('Test/Zone')
    dti.offset :o1, -18000, 3600, :TEST
    
    dti.transition 2006, 6, :o1, 1149368400
    
    assert_raises(ArgumentError) { dti.transition 2006, 5, :o2, 1146690000 }
  end
  
  def test_transition_invalid_order_year
    dti = DataTimezoneInfo.new('Test/Zone')
    dti.offset :o1, -18000, 3600, :TEST
    
    dti.transition 2006, 6, :o1, 1149368400
    
    assert_raises(ArgumentError) { dti.transition 2005, 7, :o2, 1120424400 }
  end   
  
  def test_period_for_utc
    dti = DataTimezoneInfo.new('Test/Zone')
    dti.offset :o1, -17900,    0, :TESTLMT
    dti.offset :o2, -18000, 3600, :TESTD
    dti.offset :o3, -18000,    0, :TESTS
    dti.offset :o4, -21600, 3600, :TESTD
    
    dti.transition 2000,  4, :o2, Time.utc(2000, 4,1,1,0,0).to_i
    dti.transition 2000, 10, :o3, Time.utc(2000,10,1,1,0,0).to_i
    dti.transition 2001,  3, :o2, 58847269, 24                    # (2001, 3,1,1,0,0)
    dti.transition 2001,  4, :o4, Time.utc(2001, 4,1,1,0,0).to_i
    dti.transition 2001, 10, :o3, Time.utc(2001,10,1,1,0,0).to_i
    dti.transition 2002, 10, :o3, Time.utc(2002,10,1,1,0,0).to_i
    dti.transition 2003,  2, :o2, Time.utc(2003, 2,1,1,0,0).to_i
    dti.transition 2003,  3, :o3, Time.utc(2003, 3,1,1,0,0).to_i
    
    o1 = TimezoneOffsetInfo.new(-17900, 0,    :TESTLMT)
    o2 = TimezoneOffsetInfo.new(-18000, 3600, :TESTD)
    o3 = TimezoneOffsetInfo.new(-18000, 0,    :TESTS)
    o4 = TimezoneOffsetInfo.new(-21600, 3600, :TESTD)
    
    t1 = TimezoneTransitionInfo.new(o2, o1, Time.utc(2000, 4,1,1,0,0).to_i)
    t2 = TimezoneTransitionInfo.new(o3, o2, Time.utc(2000,10,1,1,0,0).to_i)
    t3 = TimezoneTransitionInfo.new(o2, o3, Time.utc(2001, 3,1,1,0,0).to_i)
    t4 = TimezoneTransitionInfo.new(o4, o2, Time.utc(2001, 4,1,1,0,0).to_i)
    t5 = TimezoneTransitionInfo.new(o3, o4, Time.utc(2001,10,1,1,0,0).to_i)
    t6 = TimezoneTransitionInfo.new(o3, o3, Time.utc(2002,10,1,1,0,0).to_i)
    t7 = TimezoneTransitionInfo.new(o2, o3, Time.utc(2003, 2,1,1,0,0).to_i)
    t8 = TimezoneTransitionInfo.new(o3, o2, Time.utc(2003, 3,1,1,0,0).to_i)     
    
    assert_equal(TimezonePeriod.new(nil, t1), dti.period_for_utc(DateTime.new(1960, 1,1,1, 0, 0)))
    assert_equal(TimezonePeriod.new(nil, t1), dti.period_for_utc(DateTime.new(1999,12,1,0, 0, 0)))
    assert_equal(TimezonePeriod.new(nil, t1), dti.period_for_utc(Time.utc(    2000, 4,1,0,59,59)))
    assert_equal(TimezonePeriod.new(t1, t2),  dti.period_for_utc(DateTime.new(2000, 4,1,1, 0, 0)))
    assert_equal(TimezonePeriod.new(t1, t2),  dti.period_for_utc(Time.utc(    2000,10,1,0,59,59).to_i))      
    assert_equal(TimezonePeriod.new(t2, t3),  dti.period_for_utc(Time.utc(    2000,10,1,1, 0, 0)))
    assert_equal(TimezonePeriod.new(t2, t3),  dti.period_for_utc(Time.utc(    2001, 3,1,0,59,59)))
    assert_equal(TimezonePeriod.new(t3, t4),  dti.period_for_utc(Time.utc(    2001, 3,1,1, 0, 0)))
    assert_equal(TimezonePeriod.new(t3, t4),  dti.period_for_utc(Time.utc(    2001, 4,1,0,59,59)))
    assert_equal(TimezonePeriod.new(t4, t5),  dti.period_for_utc(Time.utc(    2001, 4,1,1, 0, 0)))
    assert_equal(TimezonePeriod.new(t4, t5),  dti.period_for_utc(Time.utc(    2001,10,1,0,59,59)))
    assert_equal(TimezonePeriod.new(t5, t6),  dti.period_for_utc(Time.utc(    2001,10,1,1, 0, 0)))
    assert_equal(TimezonePeriod.new(t5, t6),  dti.period_for_utc(Time.utc(    2002, 2,1,1, 0, 0)))
    assert_equal(TimezonePeriod.new(t5, t6),  dti.period_for_utc(Time.utc(    2002,10,1,0,59,59)))
    assert_equal(TimezonePeriod.new(t6, t7),  dti.period_for_utc(Time.utc(    2002,10,1,1, 0, 0)))
    assert_equal(TimezonePeriod.new(t6, t7),  dti.period_for_utc(Time.utc(    2003, 2,1,0,59,59)))
    assert_equal(TimezonePeriod.new(t7, t8),  dti.period_for_utc(Time.utc(    2003, 2,1,1, 0, 0)))
    assert_equal(TimezonePeriod.new(t7, t8),  dti.period_for_utc(Time.utc(    2003, 3,1,0,59,59)))
    assert_equal(TimezonePeriod.new(t8, nil), dti.period_for_utc(Time.utc(    2003, 3,1,1, 0, 0)))
    assert_equal(TimezonePeriod.new(t8, nil), dti.period_for_utc(Time.utc(    2004, 1,1,1, 0, 0)))
    assert_equal(TimezonePeriod.new(t8, nil), dti.period_for_utc(DateTime.new(2050, 1,1,1, 0, 0)))        
  end
    
  def test_period_for_utc_no_transitions
    dti = DataTimezoneInfo.new('Test/Zone')
    dti.offset :o1, -17900, 0, :TESTLMT
    dti.offset :o2, -18000, 0, :TEST
    
    o1 = TimezoneOffsetInfo.new(-17900, 0, :TESTLMT)
    
    assert_equal(TimezonePeriod.new(nil, nil, o1), dti.period_for_utc(DateTime.new(2005,1,1,0,0,0)))
    assert_equal(TimezonePeriod.new(nil, nil, o1), dti.period_for_utc(Time.utc(2005,1,1,0,0,0)))
    assert_equal(TimezonePeriod.new(nil, nil, o1), dti.period_for_utc(Time.utc(2005,1,1,0,0,0).to_i))       
  end
    
  def test_period_for_utc_no_offsets
    dti = DataTimezoneInfo.new('Test/Zone')
    
    assert_raises(NoOffsetsDefined) { dti.period_for_utc(DateTime.new(2005,1,1,0,0,0)) }
    assert_raises(NoOffsetsDefined) { dti.period_for_utc(Time.utc(2005,1,1,0,0,0)) }
    assert_raises(NoOffsetsDefined) { dti.period_for_utc(Time.utc(2005,1,1,0,0,0).to_i) }
  end
  
  def test_periods_for_local
    dti = DataTimezoneInfo.new('Test/Zone')
    dti.offset :o1, -17900,    0, :TESTLMT
    dti.offset :o2, -18000, 3600, :TESTD
    dti.offset :o3, -18000,    0, :TESTS
    dti.offset :o4, -21600, 3600, :TESTD
    
    dti.transition 2000,  4, :o2, 58839277, 24                   # 2000,4,2,1,0,0
    dti.transition 2000, 10, :o3, Time.utc(2000,10,2,1,0,0).to_i
    dti.transition 2001,  3, :o2, Time.utc(2001, 3,2,1,0,0).to_i
    dti.transition 2001,  4, :o4, Time.utc(2001, 4,2,1,0,0).to_i
    dti.transition 2001, 10, :o3, Time.utc(2001,10,2,1,0,0).to_i
    dti.transition 2002, 10, :o3, 58861189, 24                   # 2002,10,2,1,0,0
    dti.transition 2003,  2, :o2, Time.utc(2003, 2,2,1,0,0).to_i
    
    o1 = TimezoneOffsetInfo.new(-17900,    0, :TESTLMT)
    o2 = TimezoneOffsetInfo.new(-18000, 3600, :TESTD)
    o3 = TimezoneOffsetInfo.new(-18000,    0, :TESTS)
    o4 = TimezoneOffsetInfo.new(-21600, 3600, :TESTD)
    
    t1 = TimezoneTransitionInfo.new(o2, o1, Time.utc(2000, 4,2,1,0,0).to_i)
    t2 = TimezoneTransitionInfo.new(o3, o2, Time.utc(2000,10,2,1,0,0).to_i)
    t3 = TimezoneTransitionInfo.new(o2, o3, Time.utc(2001, 3,2,1,0,0).to_i)
    t4 = TimezoneTransitionInfo.new(o4, o2, Time.utc(2001, 4,2,1,0,0).to_i)
    t5 = TimezoneTransitionInfo.new(o3, o4, Time.utc(2001,10,2,1,0,0).to_i)
    t6 = TimezoneTransitionInfo.new(o3, o3, Time.utc(2002,10,2,1,0,0).to_i)
    t7 = TimezoneTransitionInfo.new(o2, o3, Time.utc(2003, 2,2,1,0,0).to_i)
    
    
    assert_equal([TimezonePeriod.new(nil, t1)], dti.periods_for_local(DateTime.new(1960, 1, 1, 1, 0, 0)))
    assert_equal([TimezonePeriod.new(nil, t1)], dti.periods_for_local(DateTime.new(1999,12, 1, 0, 0, 0)))
    assert_equal([TimezonePeriod.new(nil, t1)], dti.periods_for_local(Time.utc(    2000, 1, 1,10, 0, 0)))
    assert_equal([TimezonePeriod.new(nil, t1)], dti.periods_for_local(Time.utc(    2000, 4, 1,20, 1,39)))
    assert_equal([],                            dti.periods_for_local(Time.utc(    2000, 4, 1,20, 1,40)))
    assert_equal([],                            dti.periods_for_local(Time.utc(    2000, 4, 1,20,59,59)))
    assert_equal([TimezonePeriod.new(t1,  t2)], dti.periods_for_local(Time.utc(    2000, 4, 1,21, 0, 0)))
    assert_equal([TimezonePeriod.new(t1,  t2)], dti.periods_for_local(DateTime.new(2000,10, 1,19,59,59)))
    assert_equal([TimezonePeriod.new(t1,  t2),
                  TimezonePeriod.new(t2,  t3)], dti.periods_for_local(Time.utc(    2000,10, 1,20, 0, 0).to_i))   
    assert_equal([TimezonePeriod.new(t1,  t2),
                  TimezonePeriod.new(t2,  t3)], dti.periods_for_local(DateTime.new(2000,10, 1,20,59,59)))
    assert_equal([TimezonePeriod.new(t2,  t3)], dti.periods_for_local(Time.utc(    2000,10, 1,21, 0, 0)))
    assert_equal([TimezonePeriod.new(t2,  t3)], dti.periods_for_local(Time.utc(    2001, 3, 1,19,59,59)))
    assert_equal([],                            dti.periods_for_local(Time.utc(    2001, 3, 1,20, 0, 0)))
    assert_equal([],                            dti.periods_for_local(DateTime.new(2001, 3, 1,20, 30, 0)))
    assert_equal([],                            dti.periods_for_local(Time.utc(    2001, 3, 1,20,59,59).to_i))
    assert_equal([TimezonePeriod.new(t3,  t4)], dti.periods_for_local(Time.utc(    2001, 3, 1,21, 0, 0)))
    assert_equal([TimezonePeriod.new(t3,  t4)], dti.periods_for_local(Time.utc(    2001, 4, 1,19,59,59)))
    assert_equal([TimezonePeriod.new(t3,  t4),
                  TimezonePeriod.new(t4,  t5)], dti.periods_for_local(DateTime.new(2001, 4, 1,20, 0, 0)))
    assert_equal([TimezonePeriod.new(t3,  t4),
                  TimezonePeriod.new(t4,  t5)], dti.periods_for_local(Time.utc(    2001, 4, 1,20,59,59)))                  
    assert_equal([TimezonePeriod.new(t4,  t5)], dti.periods_for_local(Time.utc(    2001, 4, 1,21, 0, 0)))
    assert_equal([TimezonePeriod.new(t4,  t5)], dti.periods_for_local(Time.utc(    2001,10, 1,19,59,59)))
    assert_equal([TimezonePeriod.new(t5,  t6)], dti.periods_for_local(Time.utc(    2001,10, 1,20, 0, 0)))
    assert_equal([TimezonePeriod.new(t5,  t6)], dti.periods_for_local(Time.utc(    2002, 2, 1,20, 0, 0)))
    assert_equal([TimezonePeriod.new(t5,  t6)], dti.periods_for_local(Time.utc(    2002,10, 1,19,59,59)))
    assert_equal([TimezonePeriod.new(t6,  t7)], dti.periods_for_local(Time.utc(    2002,10, 1,20, 0, 0)))
    assert_equal([TimezonePeriod.new(t6,  t7)], dti.periods_for_local(Time.utc(    2003, 2, 1,19,59,59)))
    assert_equal([],                            dti.periods_for_local(Time.utc(    2003, 2, 1,20, 0, 0)))
    assert_equal([],                            dti.periods_for_local(Time.utc(    2003, 2, 1,20,59,59)))
    assert_equal([TimezonePeriod.new(t7, nil)], dti.periods_for_local(Time.utc(    2003, 2, 1,21, 0, 0)))
    assert_equal([TimezonePeriod.new(t7, nil)], dti.periods_for_local(Time.utc(    2004, 2, 1,20, 0, 0)))
    assert_equal([TimezonePeriod.new(t7, nil)], dti.periods_for_local(DateTime.new(2040, 2, 1,20, 0, 0)))
  end
      
  def test_periods_for_local_warsaw
    dti = DataTimezoneInfo.new('Test/Europe/Warsaw')
    dti.offset :o1, 5040,    0, :LMT
    dti.offset :o2, 5040,    0, :WMT
    dti.offset :o3, 3600,    0, :CET
    dti.offset :o4, 3600, 3600, :CEST
    
    dti.transition 1879, 12, :o2, 288925853, 120  # 1879,12,31,22,36,0
    dti.transition 1915,  8, :o3, 290485733, 120  # 1915, 8, 4,22,36,0
    dti.transition 1916,  4, :o4,  29051813,  12  # 1916, 4,30,22, 0,0
    
    o1 = TimezoneOffsetInfo.new(5040,    0, :LMT)
    o2 = TimezoneOffsetInfo.new(5040,    0, :WMT)
    o3 = TimezoneOffsetInfo.new(3600,    0, :CET)
    o4 = TimezoneOffsetInfo.new(3600, 3600, :CEST)
    
    t1 = TimezoneTransitionInfo.new(o2, o1, 288925853, 120)
    t2 = TimezoneTransitionInfo.new(o3, o2, 290485733, 120)
    t3 = TimezoneTransitionInfo.new(o4, o3,  29051813,  12)
    
    assert_equal([TimezonePeriod.new(t1, t2),
                  TimezonePeriod.new(t2, t3)], dti.periods_for_local(DateTime.new(1915,8,4,23,40,0)))      
  end
    
  def test_periods_for_local_boundary
    dti = DataTimezoneInfo.new('Test/Zone')
    dti.offset :o1, -3600, 0, :TESTD
    dti.offset :o2, -3600, 0, :TESTS
    
    dti.transition 2000, 7, :o2, Time.utc(2000,7,1,0,0,0).to_i
    
    o1 = TimezoneOffsetInfo.new(-3600, 0, :TESTD)
    o2 = TimezoneOffsetInfo.new(-3600, 0, :TESTS)
    
    t1 = TimezoneTransitionInfo.new(o2, o1, Time.utc(2000,7,1,0,0,0).to_i)
                
    # 2000-07-01 00:00:00 UTC is 2000-06-30 23:00:00 UTC-1
    # hence to find periods for local times between 2000-06-30 23:00:00
    # and 2000-07-01 00:00:00 a search has to be carried out in the next half
    # year to the one containing the date we are looking for
    
    assert_equal([TimezonePeriod.new(nil, t1)], dti.periods_for_local(Time.utc(2000,6,30,22,59,59)))
    assert_equal([TimezonePeriod.new(t1, nil)], dti.periods_for_local(Time.utc(2000,6,30,23, 0, 0)))
    assert_equal([TimezonePeriod.new(t1, nil)], dti.periods_for_local(Time.utc(2000,7, 1, 0, 0, 0)))    
  end
    
  def test_periods_for_local_no_transitions
    dti = DataTimezoneInfo.new('Test/Zone')
    dti.offset :o1, -17900, 0, :TESTLMT
    dti.offset :o2, -18000, 0, :TEST
    
    o1 = TimezoneOffsetInfo.new(-17900, 0, :TESTLMT)
    
    assert_equal([TimezonePeriod.new(nil, nil, o1)], dti.periods_for_local(DateTime.new(2005,1,1,0,0,0)))
    assert_equal([TimezonePeriod.new(nil, nil, o1)], dti.periods_for_local(Time.utc(2005,1,1,0,0,0)))
    assert_equal([TimezonePeriod.new(nil, nil, o1)], dti.periods_for_local(Time.utc(2005,1,1,0,0,0).to_i))       
  end
    
  def test_periods_for_local_no_offsets
    dti = DataTimezoneInfo.new('Test/Zone')
    
    assert_raises(NoOffsetsDefined) { dti.periods_for_local(DateTime.new(2005,1,1,0,0,0)) }
    assert_raises(NoOffsetsDefined) { dti.periods_for_local(Time.utc(2005,1,1,0,0,0)) }
    assert_raises(NoOffsetsDefined) { dti.periods_for_local(Time.utc(2005,1,1,0,0,0).to_i) }
  end
end
