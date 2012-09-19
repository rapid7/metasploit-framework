$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'test/unit'
require 'tzinfo'

include TZInfo

class TCTimeOrDateTime < Test::Unit::TestCase
  def test_initialize_time
    TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3))    
  end
  
  def test_initialize_time_local 
    tdt = TimeOrDateTime.new(Time.local(2006, 3, 24, 15, 32, 3))    
    assert_equal(Time.utc(2006, 3, 24, 15, 32, 3), tdt.to_time)    
    assert_equal('UTC', tdt.to_time.zone)
  end
  
  def test_initialize_datetime_offset
    tdt = TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3).new_offset(Rational(5, 24)))
    assert_equal(DateTime.new(2006, 3, 24, 15, 32, 3), tdt.to_datetime)
    assert_equal(0, tdt.to_datetime.offset)
  end
  
  def test_initialize_datetime
    TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3))
  end
  
  def test_initialize_int
    TimeOrDateTime.new(1143214323)
  end
  
  def test_initialize_string
    TimeOrDateTime.new('1143214323')
  end
  
  def test_to_time
    assert_equal(Time.utc(2006, 3, 24, 15, 32, 3),
      TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).to_time)
    assert_equal(Time.utc(2006, 3, 24, 15, 32, 3),
      TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).to_time)
    assert_equal(Time.utc(2006, 3, 24, 15, 32, 3),
      TimeOrDateTime.new(1143214323).to_time)
    assert_equal(Time.utc(2006, 3, 24, 15, 32, 3),
      TimeOrDateTime.new('1143214323').to_time)
  end
  
  def test_to_datetime
    assert_equal(DateTime.new(2006, 3, 24, 15, 32, 3),
      TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).to_datetime)
    assert_equal(DateTime.new(2006, 3, 24, 15, 32, 3),
      TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).to_datetime)
    assert_equal(DateTime.new(2006, 3, 24, 15, 32, 3),
      TimeOrDateTime.new(1143214323).to_datetime)
    assert_equal(DateTime.new(2006, 3, 24, 15, 32, 3),
      TimeOrDateTime.new('1143214323').to_datetime)
  end
  
  def test_to_i
    assert_equal(1143214323,
      TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).to_i)
    assert_equal(1143214323,
      TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).to_i)
    assert_equal(1143214323,
      TimeOrDateTime.new(1143214323).to_i)
    assert_equal(1143214323,
      TimeOrDateTime.new('1143214323').to_i)
  end
  
  def test_to_orig
    assert_equal(Time.utc(2006, 3, 24, 15, 32, 3),
      TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).to_orig)
    assert_equal(DateTime.new(2006, 3, 24, 15, 32, 3),
      TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).to_orig)
    assert_equal(1143214323,
      TimeOrDateTime.new(1143214323).to_orig)
    assert_equal(1143214323,
      TimeOrDateTime.new('1143214323').to_orig) 
  end
  
  def test_to_s
    assert_equal("Time: #{Time.utc(2006, 3, 24, 15, 32, 3).to_s}",
      TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).to_s)
    assert_equal("DateTime: #{DateTime.new(2006, 3, 24, 15, 32, 3)}",
      TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).to_s)
    assert_equal('Timestamp: 1143214323',
      TimeOrDateTime.new(1143214323).to_s)
    assert_equal('Timestamp: 1143214323',
      TimeOrDateTime.new('1143214323').to_s) 
  end
  
  def test_year
    assert_equal(2006, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).year)
    assert_equal(2006, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).year)
    assert_equal(2006, TimeOrDateTime.new(1143214323).year)
  end
  
  def test_mon
    assert_equal(3, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).mon)
    assert_equal(3, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).mon)
    assert_equal(3, TimeOrDateTime.new(1143214323).mon)    
  end
  
  def test_month
    assert_equal(3, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).month)
    assert_equal(3, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).month)
    assert_equal(3, TimeOrDateTime.new(1143214323).month)
  end
  
  def test_mday
    assert_equal(24, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).mday)
    assert_equal(24, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).mday)
    assert_equal(24, TimeOrDateTime.new(1143214323).mday)
  end
  
  def test_day
    assert_equal(24, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).day)
    assert_equal(24, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).day)
    assert_equal(24, TimeOrDateTime.new(1143214323).day)
  end
  
  def test_hour
    assert_equal(15, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).hour)
    assert_equal(15, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).hour)
    assert_equal(15, TimeOrDateTime.new(1143214323).hour)
  end
  
  def test_min
    assert_equal(32, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).min)
    assert_equal(32, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).min)
    assert_equal(32, TimeOrDateTime.new(1143214323).min)
  end
  
  def test_sec
    assert_equal(3, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).sec)
    assert_equal(3, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).sec)
    assert_equal(3, TimeOrDateTime.new(1143214323).sec)
  end
  
  def test_compare_timeordatetime_time
    assert_equal(-1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 4)))
    assert_equal(-1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(Time.utc(2007, 3, 24, 15, 32, 3)))
    assert_equal(0, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)))
    assert_equal(1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 2)))
    assert_equal(1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(Time.utc(2005, 3, 24, 15, 32, 3)))
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 4)))
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(Time.utc(2007, 3, 24, 15, 32, 3)))
    assert_equal(0, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)))
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 2)))
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(Time.utc(2005, 3, 24, 15, 32, 3)))
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(1960, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)))
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2040, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)))
    assert_equal(-1, TimeOrDateTime.new(1143214323) <=> TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 4)))
    assert_equal(-1, TimeOrDateTime.new(1143214323) <=> TimeOrDateTime.new(Time.utc(2007, 3, 24, 15, 32, 3)))
    assert_equal(0, TimeOrDateTime.new(1143214323) <=> TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)))
    assert_equal(1, TimeOrDateTime.new(1143214323) <=> TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 2)))
    assert_equal(1, TimeOrDateTime.new(1143214323) <=> TimeOrDateTime.new(Time.utc(2005, 3, 24, 15, 32, 3)))
  end
  
  def test_compare_timeordatetime_datetime
    assert_equal(-1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 4)))
    assert_equal(-1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(DateTime.new(2040, 3, 24, 15, 32, 3)))
    assert_equal(0, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)))
    assert_equal(1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 2)))
    assert_equal(1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(DateTime.new(1960, 3, 24, 15, 32, 3)))
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 4)))
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(DateTime.new(2040, 3, 24, 15, 32, 3)))
    assert_equal(0, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)))
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 2)))
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(DateTime.new(1960, 3, 24, 15, 32, 3)))
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(1960, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)))
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2040, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)))
    assert_equal(-1, TimeOrDateTime.new(1143214323) <=> TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 4)))
    assert_equal(-1, TimeOrDateTime.new(1143214323) <=> TimeOrDateTime.new(DateTime.new(2040, 3, 24, 15, 32, 3)))
    assert_equal(0, TimeOrDateTime.new(1143214323) <=> TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)))
    assert_equal(1, TimeOrDateTime.new(1143214323) <=> TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 2)))
    assert_equal(1, TimeOrDateTime.new(1143214323) <=> TimeOrDateTime.new(DateTime.new(1960, 3, 24, 15, 32, 3)))
  end
  
  def test_compare_timeordatetime_timestamp
    assert_equal(-1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(1143214324))
    assert_equal(-1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(1174750323))
    assert_equal(0, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(1143214323))
    assert_equal(1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(1143214322))
    assert_equal(1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(1111678323))
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(1143214324))
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(1174750323))
    assert_equal(0, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(1143214323))
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(1143214322))
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(1111678323))
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(1960, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(1143214323))
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2040, 3, 24, 15, 32, 3)) <=> TimeOrDateTime.new(1143214323))
    assert_equal(-1, TimeOrDateTime.new(1143214323) <=> TimeOrDateTime.new(1143214324))
    assert_equal(-1, TimeOrDateTime.new(1143214323) <=> TimeOrDateTime.new(1174750323))
    assert_equal(0, TimeOrDateTime.new(1143214323) <=> TimeOrDateTime.new(1143214323))
    assert_equal(1, TimeOrDateTime.new(1143214323) <=> TimeOrDateTime.new(1143214322))
    assert_equal(1, TimeOrDateTime.new(1143214323) <=> TimeOrDateTime.new(1111678323))
  end
  
  def test_compare_time
    assert_equal(-1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> Time.utc(2006, 3, 24, 15, 32, 4))
    assert_equal(-1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> Time.utc(2007, 3, 24, 15, 32, 3))
    assert_equal(0, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> Time.utc(2006, 3, 24, 15, 32, 3))
    assert_equal(1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> Time.utc(2006, 3, 24, 15, 32, 2))
    assert_equal(1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> Time.utc(2005, 3, 24, 15, 32, 3))
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> Time.utc(2006, 3, 24, 15, 32, 4))
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> Time.utc(2007, 3, 24, 15, 32, 3))
    assert_equal(0, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> Time.utc(2006, 3, 24, 15, 32, 3))
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> Time.utc(2006, 3, 24, 15, 32, 2))
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> Time.utc(2005, 3, 24, 15, 32, 3))
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(1960, 3, 24, 15, 32, 3)) <=> Time.utc(2006, 3, 24, 15, 32, 3))
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2040, 3, 24, 15, 32, 3)) <=> Time.utc(2006, 3, 24, 15, 32, 3))
    assert_equal(-1, TimeOrDateTime.new(1143214323) <=> Time.utc(2006, 3, 24, 15, 32, 4))
    assert_equal(-1, TimeOrDateTime.new(1143214323) <=> Time.utc(2007, 3, 24, 15, 32, 3))
    assert_equal(0, TimeOrDateTime.new(1143214323) <=> Time.utc(2006, 3, 24, 15, 32, 3))
    assert_equal(1, TimeOrDateTime.new(1143214323) <=> Time.utc(2006, 3, 24, 15, 32, 2))
    assert_equal(1, TimeOrDateTime.new(1143214323) <=> Time.utc(2005, 3, 24, 15, 32, 3))
  end
  
  def test_compare_datetime
    assert_equal(-1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> DateTime.new(2006, 3, 24, 15, 32, 4))
    assert_equal(-1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> DateTime.new(2040, 3, 24, 15, 32, 3))
    assert_equal(0, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> DateTime.new(2006, 3, 24, 15, 32, 3))
    assert_equal(1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> DateTime.new(2006, 3, 24, 15, 32, 2))
    assert_equal(1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> DateTime.new(1960, 3, 24, 15, 32, 3))
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> DateTime.new(2006, 3, 24, 15, 32, 4))
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> DateTime.new(2040, 3, 24, 15, 32, 3))
    assert_equal(0, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> DateTime.new(2006, 3, 24, 15, 32, 3))
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> DateTime.new(2006, 3, 24, 15, 32, 2))
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> DateTime.new(1960, 3, 24, 15, 32, 3))
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(1960, 3, 24, 15, 32, 3)) <=> DateTime.new(2006, 3, 24, 15, 32, 3))
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2040, 3, 24, 15, 32, 3)) <=> DateTime.new(2006, 3, 24, 15, 32, 3))
    assert_equal(-1, TimeOrDateTime.new(1143214323) <=> DateTime.new(2006, 3, 24, 15, 32, 4))
    assert_equal(-1, TimeOrDateTime.new(1143214323) <=> DateTime.new(2040, 3, 24, 15, 32, 3))
    assert_equal(0, TimeOrDateTime.new(1143214323) <=> DateTime.new(2006, 3, 24, 15, 32, 3))
    assert_equal(1, TimeOrDateTime.new(1143214323) <=> DateTime.new(2006, 3, 24, 15, 32, 2))
    assert_equal(1, TimeOrDateTime.new(1143214323) <=> DateTime.new(1960, 3, 24, 15, 32, 3))
  end
  
  def test_compare_timestamp
    assert_equal(-1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> 1143214324)
    assert_equal(-1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> 1174750323)
    assert_equal(0, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> 1143214323)
    assert_equal(1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> 1143214322)
    assert_equal(1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> 1111678323)
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> 1143214324)
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> 1174750323)
    assert_equal(0, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> 1143214323)
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> 1143214322)
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> 1111678323)
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(1960, 3, 24, 15, 32, 3)) <=> 1143214323)
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2040, 3, 24, 15, 32, 3)) <=> 1143214323)
    assert_equal(-1, TimeOrDateTime.new(1143214323) <=> 1143214324)
    assert_equal(-1, TimeOrDateTime.new(1143214323) <=> 1174750323)
    assert_equal(0, TimeOrDateTime.new(1143214323) <=> 1143214323)
    assert_equal(1, TimeOrDateTime.new(1143214323) <=> 1143214322)
    assert_equal(1, TimeOrDateTime.new(1143214323) <=> 1111678323)
  end
  
  def test_compare_timestamp_str
    assert_equal(-1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> '1143214324')
    assert_equal(-1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> '1174750323')
    assert_equal(0, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> '1143214323')
    assert_equal(1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> '1143214322')
    assert_equal(1, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) <=> '1111678323')
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> '1143214324')
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> '1174750323')
    assert_equal(0, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> '1143214323')
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> '1143214322')
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) <=> '1111678323')
    assert_equal(-1, TimeOrDateTime.new(DateTime.new(1960, 3, 24, 15, 32, 3)) <=> '1143214323')
    assert_equal(1, TimeOrDateTime.new(DateTime.new(2040, 3, 24, 15, 32, 3)) <=> '1143214323')
    assert_equal(-1, TimeOrDateTime.new(1143214323) <=> '1143214324')
    assert_equal(-1, TimeOrDateTime.new(1143214323) <=> '1174750323')
    assert_equal(0, TimeOrDateTime.new(1143214323) <=> '1143214323')
    assert_equal(1, TimeOrDateTime.new(1143214323) <=> '1143214322')
    assert_equal(1, TimeOrDateTime.new(1143214323) <=> '1111678323')
  end
  
  def test_eql
    assert_equal(true, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).eql?(TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3))))
    assert_equal(false, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).eql?(TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3))))
    assert_equal(false, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).eql?(TimeOrDateTime.new(1143214323)))
    assert_equal(false, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).eql?(TimeOrDateTime.new('1143214323')))
    assert_equal(false, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).eql?(TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 4))))
    assert_equal(false, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).eql?(Object.new))
    
    assert_equal(false, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).eql?(TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3))))
    assert_equal(true, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).eql?(TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3))))
    assert_equal(false, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).eql?(TimeOrDateTime.new(1143214323)))
    assert_equal(false, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).eql?(TimeOrDateTime.new('1143214323')))
    assert_equal(false, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).eql?(TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 4))))
    assert_equal(false, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).eql?(Object.new))
    
    assert_equal(false, TimeOrDateTime.new(1143214323).eql?(TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3))))
    assert_equal(false, TimeOrDateTime.new(1143214323).eql?(TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3))))
    assert_equal(true, TimeOrDateTime.new(1143214323).eql?(TimeOrDateTime.new(1143214323)))
    assert_equal(true, TimeOrDateTime.new(1143214323).eql?(TimeOrDateTime.new('1143214323')))
    assert_equal(false, TimeOrDateTime.new(1143214323).eql?(TimeOrDateTime.new(1143214324)))
    assert_equal(false, TimeOrDateTime.new(1143214323).eql?(Object.new))
  end
  
  def test_hash
    assert_equal(Time.utc(2006, 3, 24, 15, 32, 3).hash, TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).hash)
    assert_equal(DateTime.new(2006, 3, 24, 15, 32, 3).hash, TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).hash)
    assert_equal(1143214323.hash, TimeOrDateTime.new(1143214323).hash)
    assert_equal(1143214323.hash, TimeOrDateTime.new('1143214323').hash)
  end
  
  def test_add
    assert_equal(Time.utc(2006, 3, 24, 15, 32, 3), (TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) + 0).to_orig)
    assert_equal(DateTime.new(2006, 3, 24, 15, 32, 3), (TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) + 0).to_orig)
    assert_equal(1143214323, (TimeOrDateTime.new(1143214323) + 0).to_orig)
    assert_equal(Time.utc(2006, 3, 24, 15, 32, 4), (TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) + 1).to_orig)
    assert_equal(DateTime.new(2006, 3, 24, 15, 32, 4), (TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) + 1).to_orig)
    assert_equal(1143214324, (TimeOrDateTime.new(1143214323) + 1).to_orig)
    assert_equal(Time.utc(2006, 3, 24, 15, 32, 2), (TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) + (-1)).to_orig)
    assert_equal(DateTime.new(2006, 3, 24, 15, 32, 2), (TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) + (-1)).to_orig)
    assert_equal(1143214322, (TimeOrDateTime.new(1143214323) + (-1)).to_orig)
  end
  
  def test_subtract     
    assert_equal(Time.utc(2006, 3, 24, 15, 32, 3), (TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) - 0).to_orig)
    assert_equal(DateTime.new(2006, 3, 24, 15, 32, 3), (TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) - 0).to_orig)   
    assert_equal(1143214323, (TimeOrDateTime.new(1143214323) - 0).to_orig)
    assert_equal(Time.utc(2006, 3, 24, 15, 32, 2), (TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) - 1).to_orig)
    assert_equal(DateTime.new(2006, 3, 24, 15, 32, 2), (TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) - 1).to_orig)
    assert_equal(1143214322, (TimeOrDateTime.new(1143214323) - 1).to_orig)
    assert_equal(Time.utc(2006, 3, 24, 15, 32, 4), (TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)) - (-1)).to_orig)
    assert_equal(DateTime.new(2006, 3, 24, 15, 32, 4), (TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)) - (-1)).to_orig)
    assert_equal(1143214324, (TimeOrDateTime.new(1143214323) - (-1)).to_orig)
  end
  
  def test_add_with_convert
    assert_equal(Time.utc(2006, 3, 24, 15, 32, 3), TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).add_with_convert(0).to_orig)
    assert_equal(DateTime.new(2006, 3, 24, 15, 32, 3), TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).add_with_convert(0).to_orig)
    assert_equal(1143214323, TimeOrDateTime.new(1143214323).add_with_convert(0).to_orig)
    assert_equal(Time.utc(2006, 3, 24, 15, 32, 4), TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).add_with_convert(1).to_orig)
    assert_equal(DateTime.new(2006, 3, 24, 15, 32, 4), TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).add_with_convert(1).to_orig)
    assert_equal(1143214324, TimeOrDateTime.new(1143214323).add_with_convert(1).to_orig)
    assert_equal(Time.utc(2006, 3, 24, 15, 32, 2), TimeOrDateTime.new(Time.utc(2006, 3, 24, 15, 32, 3)).add_with_convert(-1).to_orig)
    assert_equal(DateTime.new(2006, 3, 24, 15, 32, 2), TimeOrDateTime.new(DateTime.new(2006, 3, 24, 15, 32, 3)).add_with_convert(-1).to_orig)
    assert_equal(1143214322, TimeOrDateTime.new(1143214323).add_with_convert(-1).to_orig)
    
    assert_equal(DateTime.new(1969, 12, 31, 23, 59, 59), TimeOrDateTime.new(Time.utc(1970, 1, 1, 0, 0, 0)).add_with_convert(-1).to_orig)
    assert_equal(DateTime.new(2038, 1, 19, 3, 14, 8), TimeOrDateTime.new(Time.utc(2038, 1, 19, 3, 14, 7)).add_with_convert(1).to_orig)
  end
  
  def test_wrap_time
    t = TimeOrDateTime.wrap(Time.utc(2006, 3, 24, 15, 32, 3))
    assert_instance_of(TimeOrDateTime, t)
    assert_equal(Time.utc(2006, 3, 24, 15, 32, 3), t.to_orig)
  end
  
  def test_wrap_datetime
    t = TimeOrDateTime.wrap(DateTime.new(2006, 3, 24, 15, 32, 3))
    assert_instance_of(TimeOrDateTime, t)
    assert_equal(DateTime.new(2006, 3, 24, 15, 32, 3), t.to_orig)
  end
  
  def test_wrap_timestamp
    t = TimeOrDateTime.wrap(1143214323)
    assert_instance_of(TimeOrDateTime, t)
    assert_equal(1143214323, t.to_orig)
  end 
  
  def test_wrap_timestamp_str
    t = TimeOrDateTime.wrap('1143214323')
    assert_instance_of(TimeOrDateTime, t)
    assert_equal(1143214323, t.to_orig)
  end

  def test_wrap_timeordatetime
    t = TimeOrDateTime.new(1143214323)
    t2 = TimeOrDateTime.wrap(t)
    assert_same(t, t2)    
  end
  
  def test_wrap_block_time
    assert_equal(Time.utc(2006, 3, 24, 15, 32, 4), TimeOrDateTime.wrap(Time.utc(2006, 3, 24, 15, 32, 3)) {|t|
      assert_instance_of(TimeOrDateTime, t)
      assert_equal(Time.utc(2006, 3, 24, 15, 32, 3), t.to_orig)
      t + 1
    })
  end
  
  def test_wrap_block_datetime
    assert_equal(DateTime.new(2006, 3, 24, 15, 32, 4), TimeOrDateTime.wrap(DateTime.new(2006, 3, 24, 15, 32, 3)) {|t|
      assert_instance_of(TimeOrDateTime, t)
      assert_equal(DateTime.new(2006, 3, 24, 15, 32, 3), t.to_orig)
      t + 1
    })
  end
  
  def test_wrap_block_timestamp
    assert_equal(1143214324, TimeOrDateTime.wrap(1143214323) {|t|
      assert_instance_of(TimeOrDateTime, t)
      assert_equal(1143214323, t.to_orig)
      t + 1
    })
  end
  
  def test_wrap_block_timestamp_str
    assert_equal(1143214324, TimeOrDateTime.wrap('1143214323') {|t|
      assert_instance_of(TimeOrDateTime, t)
      assert_equal(1143214323, t.to_orig)
      t + 1
    })
  end
  
  def test_wrap_block_timeordatetime
    t1 = TimeOrDateTime.new(1143214323)
        
    t2 = TimeOrDateTime.wrap(t1) {|t|
      assert_same(t1, t)
      t + 1           
    }
      
    assert t2
    assert_instance_of(TimeOrDateTime, t2)
    assert_equal(1143214324, t2.to_orig)
  end
end
