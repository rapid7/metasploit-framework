$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'test/unit'
require File.join(File.dirname(__FILE__), 'test_utils')
require 'tzinfo'

include TZInfo

class TCTimezone < Test::Unit::TestCase

  class BlockCalled < StandardError
  end
  
  class TestTimezone < Timezone
    def self.new(identifier, period_for_utc = nil, periods_for_local = nil, expected = nil)
      t = super()
      t.send(:setup, identifier, period_for_utc, periods_for_local, expected)
      t
    end
    
    def identifier
      @identifier
    end
    
    def period_for_utc(utc)
      utc = TimeOrDateTime.wrap(utc)
      raise "Unexpected utc #{utc} in period_for_utc" unless @expected.eql?(utc)
      @period_for_utc
    end
    
    def periods_for_local(local)            
      local = TimeOrDateTime.wrap(local)
      raise "Unexpected local #{local} in periods_for_local" unless @expected.eql?(local)
      @periods_for_local.clone        
    end
    
    private
      def setup(identifier, period_for_utc, periods_for_local, expected)
        @identifier = identifier
        @period_for_utc = period_for_utc
        @periods_for_local = periods_for_local || []
        @expected = TimeOrDateTime.wrap(expected)
      end
  end
  
  def setup
    @orig_default_dst = Timezone.default_dst
  end
  
  def teardown
    Timezone.default_dst = @orig_default_dst
  end
  
  def test_default_dst_initial_value
    assert_nil(Timezone.default_dst)
  end
  
  def test_set_default_dst
    Timezone.default_dst = true
    assert_equal(true, Timezone.default_dst)
    Timezone.default_dst = false
    assert_equal(false, Timezone.default_dst)
    Timezone.default_dst = nil
    assert_nil(Timezone.default_dst)
    Timezone.default_dst = 0
    assert_equal(true, Timezone.default_dst)
  end
  
  def test_get_valid_1
    tz = Timezone.get('Europe/London')
    
    assert_kind_of(DataTimezone, tz)
    assert_equal('Europe/London', tz.identifier)
  end
  
  def test_get_valid_2
    tz = Timezone.get('UTC')
    
    assert_kind_of(LinkedTimezone, tz)    
    assert_equal('UTC', tz.identifier)
  end
  
  def test_get_valid_3
    tz = Timezone.get('America/Argentina/Buenos_Aires')
    
    assert_kind_of(DataTimezone, tz)
    assert_equal('America/Argentina/Buenos_Aires', tz.identifier)
  end
  
  def test_get_same_instance
    tz1 = Timezone.get('Europe/London')
    tz2 = Timezone.get('Europe/London')
    assert_same(tz1, tz2)
  end
  
  def test_get_not_exist
    assert_raises(InvalidTimezoneIdentifier) { Timezone.get('Nowhere/Special') }
  end
  
  def test_get_invalid
    assert_raises(InvalidTimezoneIdentifier) { Timezone.get('../Definitions/UTC') }
  end
  
  def test_get_nil
    assert_raises(InvalidTimezoneIdentifier) { Timezone.get(nil) }
  end
  
  def test_get_plus
    tz = Timezone.get('Etc/GMT+1')
    
    assert_equal('Etc/GMT+1', tz.identifier)
  end
  
  def test_get_minus
    tz = Timezone.get('Etc/GMT-1')
    
    assert_equal('Etc/GMT-1', tz.identifier)
  end
  
  def test_get_case    
    Timezone.get('Europe/Prague')
    assert_raises(InvalidTimezoneIdentifier) { Timezone.get('Europe/prague') }
  end
  
  def test_get_proxy_valid
    proxy = Timezone.get_proxy('Europe/London')
    assert_kind_of(TimezoneProxy, proxy)
    assert_equal('Europe/London', proxy.identifier)
  end
  
  def test_get_proxy_not_exist
    proxy = Timezone.get_proxy('Not/There')
    assert_kind_of(TimezoneProxy, proxy)
    assert_equal('Not/There', proxy.identifier)
  end
  
  def test_get_proxy_invalid
    proxy = Timezone.get_proxy('../Invalid/Identifier')
    assert_kind_of(TimezoneProxy, proxy)
    assert_equal('../Invalid/Identifier', proxy.identifier)
  end
  
  def test_get_tainted_loaded
    Timezone.get('Europe/Andorra')
  
    safe_test do
      tz = Timezone.get('Europe/Andorra'.taint)
      assert_equal('Europe/Andorra', tz.identifier)
    end
  end
  
  # Disable test in Ruby 1.9. See:
  # http://groups.google.com/group/ruby-talk-google/browse_thread/thread/170a7205555cedfc
  # It doesn't appear to be possible to require a file from the load path in Ruby 1.9.
  if RUBY_VERSION !~ /^1.9/
    def test_get_tainted_not_loaded
      safe_test do
        tz = Timezone.get('Europe/Amsterdam'.taint)
        assert_equal('Europe/Amsterdam', tz.identifier)
      end
    end
  end
  
  def test_new_no_args
    tz = Timezone.new
    
    assert_raises(UnknownTimezone) { tz.identifier }
    assert_raises(UnknownTimezone) { tz.friendly_identifier }
    assert_raises(UnknownTimezone) { tz.utc_to_local(DateTime.new(2006,1,1,1,0,0)) }
    assert_raises(UnknownTimezone) { tz.local_to_utc(DateTime.new(2006,1,1,1,0,0)) }
    assert_raises(UnknownTimezone) { tz.period_for_utc(DateTime.new(2006,1,1,1,0,0)) }
    assert_raises(UnknownTimezone) { tz.periods_for_local(DateTime.new(2006,1,1,1,0,0)) }
    assert_raises(UnknownTimezone) { tz.period_for_local(DateTime.new(2006,1,1,1,0,0)) }
    assert_raises(UnknownTimezone) { tz.now }
    assert_raises(UnknownTimezone) { tz.current_period_and_time } 
  end
  
  def test_new_nil
    tz = Timezone.new(nil)
    
    assert_raises(UnknownTimezone) { tz.identifier }
    assert_raises(UnknownTimezone) { tz.friendly_identifier }
    assert_raises(UnknownTimezone) { tz.utc_to_local(DateTime.new(2006,1,1,1,0,0)) }
    assert_raises(UnknownTimezone) { tz.local_to_utc(DateTime.new(2006,1,1,1,0,0)) }
    assert_raises(UnknownTimezone) { tz.period_for_utc(DateTime.new(2006,1,1,1,0,0)) }
    assert_raises(UnknownTimezone) { tz.periods_for_local(DateTime.new(2006,1,1,1,0,0)) }
    assert_raises(UnknownTimezone) { tz.period_for_local(DateTime.new(2006,1,1,1,0,0)) }
    assert_raises(UnknownTimezone) { tz.now }
    assert_raises(UnknownTimezone) { tz.current_period_and_time } 
  end
  
  def test_new_arg
    tz = Timezone.new('Europe/London')
    assert_same(Timezone.get('Europe/London'), tz)    
  end
  
  def test_new_arg_not_exist    
    assert_raises(InvalidTimezoneIdentifier) { Timezone.new('Nowhere/Special') }
  end 
  
  def test_all
    all = Timezone.all
    expected = Indexes::Timezones.timezones.collect {|identifier| Timezone.get_proxy(identifier)}
    assert_equal(expected, all)
  end
  
  def test_all_identifiers
    all = Timezone.all_identifiers
    assert_equal(Indexes::Timezones.timezones, all)
  end
  
  def test_all_data_zones
    all_data = Timezone.all_data_zones
    expected = Indexes::Timezones.data_timezones.collect {|identifier| Timezone.get_proxy(identifier)}
    assert_equal(expected, all_data)
  end
  
  def test_all_data_zone_identifiers
    all_data = Timezone.all_data_zone_identifiers
    assert_equal(Indexes::Timezones.data_timezones, all_data)
  end
  
  def test_all_linked_zones
    all_linked = Timezone.all_linked_zones
    expected = Indexes::Timezones.linked_timezones.collect {|identifier| Timezone.get_proxy(identifier)}
    assert_equal(expected, all_linked)
  end
  
  def test_all_linked_zone_identifiers
    all_linked = Timezone.all_linked_zone_identifiers
    assert_equal(Indexes::Timezones.linked_timezones, all_linked)
  end
  
  def test_all_country_zones
    # Probably should relax this test - just need all the zones, don't care
    # about order.
    expected = Country.all.inject([]) {|result,country|
      result += country.zones
    }
    expected.uniq!
    
    all_country_zones = Timezone.all_country_zones
    assert_equal(expected, all_country_zones)
    
    all_country_zone_identifiers = Timezone.all_country_zone_identifiers
    assert_equal(all_country_zone_identifiers.length, all_country_zones.length)
    
    all_country_zones.each {|zone|
      assert_kind_of(TimezoneProxy, zone)
      assert(all_country_zone_identifiers.include?(zone.identifier))
    }            
  end
  
  def test_all_country_zone_identifiers
    # Probably should relax this test - just need all the zones, don't care
    # about order.
    expected = Country.all.inject([]) {|result,country|
      result += country.zone_identifiers
    }
    expected.uniq!
        
    assert_equal(expected, Timezone.all_country_zone_identifiers)
  end
  
  def test_us_zones   
    # Probably should relax this test - just need all the zones, don't care
    # about order.
    us_zones = Timezone.us_zones
    assert_equal(Country.get('US').zones.uniq, us_zones)
    
    us_zone_identifiers = Timezone.us_zone_identifiers
    assert_equal(us_zone_identifiers.length, us_zones.length)
    
    us_zones.each {|zone|
      assert_kind_of(TimezoneProxy, zone)
      assert(us_zone_identifiers.include?(zone.identifier))
    }
  end
  
  def test_us_zone_identifiers
    # Probably should relax this test - just need all the zones, don't care
    # about order.        
    assert_equal(Country.get('US').zone_identifiers.uniq, Timezone.us_zone_identifiers)
  end    
  
  def test_identifier
    assert_raises(UnknownTimezone) { Timezone.new.identifier }    
    assert_equal('Europe/Paris', TestTimezone.new('Europe/Paris').identifier)
  end
  
  def test_name
    assert_raises(UnknownTimezone) { Timezone.new.name }    
    assert_equal('Europe/Paris', TestTimezone.new('Europe/Paris').name)    
  end
  
  def test_friendly_identifier
    assert_equal('Paris', TestTimezone.new('Europe/Paris').friendly_identifier(true))
    assert_equal('Europe - Paris', TestTimezone.new('Europe/Paris').friendly_identifier(false))
    assert_equal('Europe - Paris', TestTimezone.new('Europe/Paris').friendly_identifier)
    assert_equal('Knox, Indiana', TestTimezone.new('America/Indiana/Knox').friendly_identifier(true))
    assert_equal('America - Knox, Indiana', TestTimezone.new('America/Indiana/Knox').friendly_identifier(false))
    assert_equal('America - Knox, Indiana', TestTimezone.new('America/Indiana/Knox').friendly_identifier)
    assert_equal('Dumont D\'Urville', TestTimezone.new('Antarctica/DumontDUrville').friendly_identifier(true))
    assert_equal('Antarctica - Dumont D\'Urville', TestTimezone.new('Antarctica/DumontDUrville').friendly_identifier(false))
    assert_equal('Antarctica - Dumont D\'Urville', TestTimezone.new('Antarctica/DumontDUrville').friendly_identifier)
    assert_equal('McMurdo', TestTimezone.new('Antarctica/McMurdo').friendly_identifier(true))
    assert_equal('Antarctica - McMurdo', TestTimezone.new('Antarctica/McMurdo').friendly_identifier(false))
    assert_equal('Antarctica - McMurdo', TestTimezone.new('Antarctica/McMurdo').friendly_identifier)
    assert_equal('GMT+1', TestTimezone.new('Etc/GMT+1').friendly_identifier(true))
    assert_equal('Etc - GMT+1', TestTimezone.new('Etc/GMT+1').friendly_identifier(false))
    assert_equal('Etc - GMT+1', TestTimezone.new('Etc/GMT+1').friendly_identifier)
    assert_equal('UTC', TestTimezone.new('UTC').friendly_identifier(true))
    assert_equal('UTC', TestTimezone.new('UTC').friendly_identifier(false))
    assert_equal('UTC', TestTimezone.new('UTC').friendly_identifier)
  end
  
  def test_to_s
    assert_equal('Europe - Paris', TestTimezone.new('Europe/Paris').to_s)
    assert_equal('America - Knox, Indiana', TestTimezone.new('America/Indiana/Knox').to_s)
    assert_equal('Antarctica - Dumont D\'Urville', TestTimezone.new('Antarctica/DumontDUrville').to_s)
    assert_equal('Antarctica - McMurdo', TestTimezone.new('Antarctica/McMurdo').to_s)
    assert_equal('Etc - GMT+1', TestTimezone.new('Etc/GMT+1').to_s)
    assert_equal('UTC', TestTimezone.new('UTC').to_s)
  end    
    
  def test_period_for_local
    dt = DateTime.new(2005,2,18,16,24,23)
    dt2 = DateTime.new(2005,2,18,16,24,23).new_offset(Rational(5,24))
    t = Time.utc(2005,2,18,16,24,23)
    t2 = Time.local(2005,2,18,16,24,23)
    ts = t.to_i
    
    o1 = TimezoneOffsetInfo.new(0, 0, :GMT)
    o2 = TimezoneOffsetInfo.new(0, 3600, :BST)
        
    period = TimezonePeriod.new(
      TimezoneTransitionInfo.new(o1, o2, 1099184400),
      TimezoneTransitionInfo.new(o2, o1, 1111885200))
    
    dt_period = TestTimezone.new('Europe/London', nil, [period], dt).period_for_local(dt)
    dt2_period = TestTimezone.new('Europe/London', nil, [period], dt2).period_for_local(dt2)
    t_period = TestTimezone.new('Europe/London', nil, [period], t).period_for_local(t)
    t2_period = TestTimezone.new('Europe/London', nil, [period], t2).period_for_local(t2)
    ts_period = TestTimezone.new('Europe/London', nil, [period], ts).period_for_local(ts)        
    
    assert_equal(period, dt_period)
    assert_equal(period, dt2_period)
    assert_equal(period, t_period)
    assert_equal(period, t2_period)
    assert_equal(period, ts_period)    
  end
  
  def test_period_for_local_invalid
    dt = DateTime.new(2004,4,4,2,30,0)
    tz = TestTimezone.new('America/New_York', nil, [], dt)
    
    assert_raises(PeriodNotFound) do
      tz.period_for_local(dt)
    end
  end
  
  def test_period_for_local_ambiguous    
    o1 = TimezoneOffsetInfo.new(-18000, 0, :EST)
    o2 = TimezoneOffsetInfo.new(-18000, 3600, :EDT)
    
    t1 = TimezoneTransitionInfo.new(o2, o1, 1081062000)
    t2 = TimezoneTransitionInfo.new(o1, o2, 1099202400)
    t3 = TimezoneTransitionInfo.new(o2, o1, 1112511600)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(t2, t3)
    
    dt = DateTime.new(2004,10,31,1, 0,0)
    t = Time.utc(2004,10,31,1,30,0)
    i = Time.utc(2004,10,31,1,59,59).to_i
    
    dt_tz = TestTimezone.new('America/New_York', nil, [p1, p2], dt)
    t_tz = TestTimezone.new('America/New_York', nil, [p1, p2], t)
    i_tz = TestTimezone.new('America/New_York', nil, [p1, p2], i)
        
    assert_raises(AmbiguousTime) { dt_tz.period_for_local(dt) }
    assert_raises(AmbiguousTime) { t_tz.period_for_local(t) }
    assert_raises(AmbiguousTime) { i_tz.period_for_local(i) }
  end
  
  def test_period_for_local_not_found
    o1 = TimezoneOffsetInfo.new(-18000, 0, :EST)
    o2 = TimezoneOffsetInfo.new(-18000, 3600, :EDT)
    
    t1 = TimezoneTransitionInfo.new(o1, o2, 1067148000)
    t2 = TimezoneTransitionInfo.new(o2, o1, 1081062000)
    t3 = TimezoneTransitionInfo.new(o1, o2, 1099202400)    
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(t2, t3)
    
    dt = DateTime.new(2004,4,4,2,0,0)
    t = Time.utc(2004,4,4,2,30,0)
    i = Time.utc(2004,4,4,2,59,59).to_i
    
    dt_tz = TestTimezone.new('America/New_York', nil, [], dt)
    t_tz = TestTimezone.new('America/New_York', nil, [], t)
    i_tz = TestTimezone.new('America/New_York', nil, [], i)
        
    assert_raises(PeriodNotFound) { dt_tz.period_for_local(dt) }
    assert_raises(PeriodNotFound) { t_tz.period_for_local(t) }
    assert_raises(PeriodNotFound) { i_tz.period_for_local(i) }
  end
  
  def test_period_for_local_default_dst_set_true
    Timezone.default_dst = true
    
    o1 = TimezoneOffsetInfo.new(-18000, 0, :EST)
    o2 = TimezoneOffsetInfo.new(-18000, 3600, :EDT)
    
    t1 = TimezoneTransitionInfo.new(o2, o1, 1081062000)
    t2 = TimezoneTransitionInfo.new(o1, o2, 1099202400)
    t3 = TimezoneTransitionInfo.new(o2, o1, 1112511600)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(t2, t3)
    
    dt = DateTime.new(2004,10,31,1,30,0)
    
    tz = TestTimezone.new('America/New_York', nil, [p1, p2], dt)
    
    assert_equal(p1, tz.period_for_local(dt))
    assert_equal(p1, tz.period_for_local(dt, true))
    assert_equal(p2, tz.period_for_local(dt, false))
    assert_raises(AmbiguousTime) { tz.period_for_local(dt, nil) }
  end
  
  def test_period_for_local_default_dst_set_false
    Timezone.default_dst = false
    
    o1 = TimezoneOffsetInfo.new(-18000, 0, :EST)
    o2 = TimezoneOffsetInfo.new(-18000, 3600, :EDT)
    
    t1 = TimezoneTransitionInfo.new(o2, o1, 1081062000)
    t2 = TimezoneTransitionInfo.new(o1, o2, 1099202400)
    t3 = TimezoneTransitionInfo.new(o2, o1, 1112511600)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(t2, t3)
    
    dt = DateTime.new(2004,10,31,1,30,0)
    
    tz = TestTimezone.new('America/New_York', nil, [p1, p2], dt)
    
    assert_equal(p2, tz.period_for_local(dt))
    assert_equal(p1, tz.period_for_local(dt, true))
    assert_equal(p2, tz.period_for_local(dt, false))
    assert_raises(AmbiguousTime) { tz.period_for_local(dt, nil) }
  end
  
  def test_period_for_local_dst_flag_resolved
    o1 = TimezoneOffsetInfo.new(-18000, 0, :EST)
    o2 = TimezoneOffsetInfo.new(-18000, 3600, :EDT)
    
    t1 = TimezoneTransitionInfo.new(o2, o1, 1081062000)
    t2 = TimezoneTransitionInfo.new(o1, o2, 1099202400)
    t3 = TimezoneTransitionInfo.new(o2, o1, 1112511600)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(t2, t3)
    
    dt = DateTime.new(2004,10,31,1,30,0)
    
    tz = TestTimezone.new('America/New_York', nil, [p1, p2], dt)

    assert_equal(p1, tz.period_for_local(dt, true))
    assert_equal(p2, tz.period_for_local(dt, false))
    assert_equal(p1, tz.period_for_local(dt, true) {|periods| raise BlockCalled, 'should not be called' })
    assert_equal(p2, tz.period_for_local(dt, false) {|periods| raise BlockCalled, 'should not be called' })
  end
  
  def test_period_for_local_dst_block_called
    o1 = TimezoneOffsetInfo.new(-18000, 0, :EST)
    o2 = TimezoneOffsetInfo.new(-18000, 3600, :EDT)
    
    t1 = TimezoneTransitionInfo.new(o2, o1, 1081062000)
    t2 = TimezoneTransitionInfo.new(o1, o2, 1099202400)
    t3 = TimezoneTransitionInfo.new(o2, o1, 1112511600)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(t2, t3)
    
    dt = DateTime.new(2004,10,31,1,30,0)
    
    tz = TestTimezone.new('America/New_York', nil, [p1, p2], dt)
    
    assert_raises(BlockCalled) {
      tz.period_for_local(dt) {|periods|        
        assert_equal([p1, p2], periods)
        
        # raise exception to test that the block was called
        raise BlockCalled, 'should be raised'
      }
    }
    
    assert_equal(p1, tz.period_for_local(dt) {|periods| periods.first})
    assert_equal(p2, tz.period_for_local(dt) {|periods| periods.last})
    assert_equal(p1, tz.period_for_local(dt) {|periods| [periods.first]})
    assert_equal(p2, tz.period_for_local(dt) {|periods| [periods.last]})
  end
  
  def test_period_for_local_dst_cannot_resolve
    # At midnight local time on Aug 5 1915 in Warsaw, the clocks were put back
    # 24 minutes and both periods were non-DST. Hence the block should be
    # called regardless of the value of the Boolean dst parameter.
    
    o0 = TimezoneOffsetInfo.new(5040, 0, :LMT)
    o1 = TimezoneOffsetInfo.new(5040, 0, :WMT)
    o2 = TimezoneOffsetInfo.new(3600, 0, :CET)
    o3 = TimezoneOffsetInfo.new(3600, 3600, :CEST)
    
    t1 = TimezoneTransitionInfo.new(o1, o0, 288925853, 120)
    t2 = TimezoneTransitionInfo.new(o2, o1, 290485733, 120)
    t3 = TimezoneTransitionInfo.new(o3, o2, 29051813, 12)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(t2, t3)
    
    dt = DateTime.new(1915,8,4,23,40,0)
    
    tz = TestTimezone.new('Europe/Warsaw', nil, [p1, p2], dt)
        
    assert_raises(BlockCalled) {
      tz.period_for_local(dt, true) {|periods|
        assert_equal([p1, p2], periods)        
        raise BlockCalled, 'should be raised'
      }
    }
    
    assert_raises(BlockCalled) {
      tz.period_for_local(dt, false) {|periods|
        assert_equal([p1, p2], periods)
        raise BlockCalled, 'should be raised'
      }
    }    
  end
  
  def test_period_for_local_block_ambiguous
    o1 = TimezoneOffsetInfo.new(-18000, 0, :EST)
    o2 = TimezoneOffsetInfo.new(-18000, 3600, :EDT)
    
    t1 = TimezoneTransitionInfo.new(o2, o1, 1081062000)
    t2 = TimezoneTransitionInfo.new(o1, o2, 1099202400)
    t3 = TimezoneTransitionInfo.new(o2, o1, 1112511600)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(t2, t3)
    
    dt = DateTime.new(2004,10,31,1,30,0)
    
    tz = TestTimezone.new('America/New_York', nil, [p1, p2], dt)
        
    assert_raises(AmbiguousTime) do
      tz.period_for_local(dt) {|periods| nil}
    end
    
    assert_raises(AmbiguousTime) do
      tz.period_for_local(dt) {|periods| periods}
    end
    
    assert_raises(AmbiguousTime) do
      tz.period_for_local(dt) {|periods| []}
    end
    
    assert_raises(AmbiguousTime) do
      tz.period_for_local(dt) {|periods| raise AmbiguousTime, 'Ambiguous time'}
    end
  end
   
  def test_utc_to_local
    dt = DateTime.new(2005,6,18,16,24,23)
    dt2 = DateTime.new(2005,6,18,16,24,23).new_offset(Rational(5,24))
    t = Time.utc(2005,6,18,16,24,23)
    t2 = Time.local(2005,6,18,16,24,23)
    ts = t.to_i
    
    o1 = TimezoneOffsetInfo.new(0, 0, :GMT)
    o2 = TimezoneOffsetInfo.new(0, 3600, :BST)
        
    period = TimezonePeriod.new(
      TimezoneTransitionInfo.new(o2, o1, 1111885200),
      TimezoneTransitionInfo.new(o1, o2, 1130634000))
        
    assert_equal(DateTime.new(2005,6,18,17,24,23), TestTimezone.new('Europe/London', period, [], dt).utc_to_local(dt))   
    assert_equal(DateTime.new(2005,6,18,17,24,23), TestTimezone.new('Europe/London', period, [], dt2).utc_to_local(dt2))    
    assert_equal(Time.utc(2005,6,18,17,24,23), TestTimezone.new('Europe/London', period, [], t).utc_to_local(t))
    assert_equal(Time.utc(2005,6,18,17,24,23), TestTimezone.new('Europe/London', period, [], t2).utc_to_local(t2))
    assert_equal(Time.utc(2005,6,18,17,24,23).to_i, TestTimezone.new('Europe/London', period, [], ts).utc_to_local(ts))
  end
  
  def test_utc_to_local_offset
    dt = DateTime.new(2005,6,18,16,24,23)
    dt2 = DateTime.new(2005,6,18,16,24,23).new_offset(Rational(5,24))
    t = Time.utc(2005,6,18,16,24,23)
    t2 = Time.local(2005,6,18,16,24,23)
    
    o1 = TimezoneOffsetInfo.new(0, 0, :GMT)
    o2 = TimezoneOffsetInfo.new(0, 3600, :BST)
        
    period = TimezonePeriod.new(
      TimezoneTransitionInfo.new(o2, o1, 1111885200),
      TimezoneTransitionInfo.new(o1, o2, 1130634000))
    
    assert_equal(0, TestTimezone.new('Europe/London', period, [], dt).utc_to_local(dt).offset)
    assert_equal(0, TestTimezone.new('Europe/London', period, [], dt2).utc_to_local(dt2).offset)
    assert_equal(0, TestTimezone.new('Europe/London', period, [], t).utc_to_local(t).utc_offset)
    assert_equal('UTC', TestTimezone.new('Europe/London', period, [], t).utc_to_local(t).zone)
    assert_equal(0, TestTimezone.new('Europe/London', period, [], t2).utc_to_local(t2).utc_offset)
    assert_equal('UTC', TestTimezone.new('Europe/London', period, [], t2).utc_to_local(t2).zone)
  end
  
  def test_local_to_utc
    dt = DateTime.new(2005,6,18,16,24,23)
    dt2 = DateTime.new(2005,6,18,16,24,23)
    t = Time.utc(2005,6,18,16,24,23)
    t2 = Time.local(2005,6,18,16,24,23)
    ts = t.to_i
        
    o1 = TimezoneOffsetInfo.new(0, 0, :GMT)
    o2 = TimezoneOffsetInfo.new(0, 3600, :BST)
        
    period = TimezonePeriod.new(
      TimezoneTransitionInfo.new(o2, o1, 1111885200),
      TimezoneTransitionInfo.new(o1, o2, 1130634000))
    
    assert_equal(DateTime.new(2005,6,18,15,24,23), TestTimezone.new('Europe/London', nil, [period], dt).local_to_utc(dt))
    assert_equal(DateTime.new(2005,6,18,15,24,23), TestTimezone.new('Europe/London', nil, [period], dt2).local_to_utc(dt2))    
    assert_equal(Time.utc(2005,6,18,15,24,23), TestTimezone.new('Europe/London', nil, [period], t).local_to_utc(t))
    assert_equal(Time.utc(2005,6,18,15,24,23), TestTimezone.new('Europe/London', nil, [period], t2).local_to_utc(t2))
    assert_equal(Time.utc(2005,6,18,15,24,23).to_i, TestTimezone.new('Europe/London', nil, [period], ts).local_to_utc(ts))
  end
  
  def test_local_to_utc_offset
    dt = DateTime.new(2005,6,18,16,24,23)
    dt2 = DateTime.new(2005,6,18,16,24,23).new_offset(Rational(5,24))
    t = Time.utc(2005,6,18,16,24,23)
    t2 = Time.local(2005,6,18,16,24,23)
    
    o1 = TimezoneOffsetInfo.new(0, 0, :GMT)
    o2 = TimezoneOffsetInfo.new(0, 3600, :BST)
        
    period = TimezonePeriod.new(
      TimezoneTransitionInfo.new(o2, o1, 1111885200),
      TimezoneTransitionInfo.new(o1, o2, 1130634000))
    
    assert_equal(0, TestTimezone.new('Europe/London', nil, [period], dt).local_to_utc(dt).offset)
    assert_equal(0, TestTimezone.new('Europe/London', nil, [period], dt2).local_to_utc(dt2).offset)
    assert_equal(0, TestTimezone.new('Europe/London', nil, [period], t).local_to_utc(t).utc_offset)
    assert_equal('UTC', TestTimezone.new('Europe/London', nil, [period], t).local_to_utc(t).zone)
    assert_equal(0, TestTimezone.new('Europe/London', nil, [period], t2).local_to_utc(t2).utc_offset)
    assert_equal('UTC', TestTimezone.new('Europe/London', nil, [period], t2).local_to_utc(t2).zone)
  end
  
  def test_local_to_utc_invalid
    dt = DateTime.new(2004,4,4,2,30,0)
    tz = TestTimezone.new('America/New_York', nil, [], dt)        
    assert_raises(PeriodNotFound) { tz.local_to_utc(dt) }
    
    t = Time.utc(2004,4,4,2,30,0)
    tz = TestTimezone.new('America/New_York', nil, [], t)        
    assert_raises(PeriodNotFound) { tz.local_to_utc(t) }
    
    i = Time.utc(2004,4,4,2,30,0).to_i
    tz = TestTimezone.new('America/New_York', nil, [], i)        
    assert_raises(PeriodNotFound) { tz.local_to_utc(i) }    
  end
  
  def test_local_to_utc_ambiguous
    o1 = TimezoneOffsetInfo.new(-18000, 0, :EST)
    o2 = TimezoneOffsetInfo.new(-18000, 3600, :EDT)
    
    t1 = TimezoneTransitionInfo.new(o2, o1, 1081062000)
    t2 = TimezoneTransitionInfo.new(o1, o2, 1099202400)
    t3 = TimezoneTransitionInfo.new(o2, o1, 1112511600)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(t2, t3)
    
    dt = DateTime.new(2004,10,31,1,30,0)    
    tz = TestTimezone.new('America/New_York', nil, [p1, p2], dt)
    assert_raises(AmbiguousTime) { tz.local_to_utc(dt) }
    
    t = Time.utc(2004,10,31,1,30,0)
    tz = TestTimezone.new('America/New_York', nil, [p1, p2], t)
    assert_raises(AmbiguousTime) { tz.local_to_utc(t) }

    i = Time.utc(2004,10,31,1,30,0).to_i
    tz = TestTimezone.new('America/New_York', nil, [p1, p2], i)
    assert_raises(AmbiguousTime) { tz.local_to_utc(i) }    
  end
  
  def test_local_to_utc_not_found
    o1 = TimezoneOffsetInfo.new(-18000, 0, :EST)
    o2 = TimezoneOffsetInfo.new(-18000, 3600, :EDT)
    
    t1 = TimezoneTransitionInfo.new(o1, o2, 1067148000)
    t2 = TimezoneTransitionInfo.new(o2, o1, 1081062000)
    t3 = TimezoneTransitionInfo.new(o1, o2, 1099202400)    
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(t2, t3)
    
    dt = DateTime.new(2004,4,4,2,0,0)
    t = Time.utc(2004,4,4,2,30,0)
    i = Time.utc(2004,4,4,2,59,59).to_i
    
    dt_tz = TestTimezone.new('America/New_York', nil, [], dt)
    t_tz = TestTimezone.new('America/New_York', nil, [], t)
    i_tz = TestTimezone.new('America/New_York', nil, [], i)
        
    assert_raises(PeriodNotFound) { dt_tz.local_to_utc(dt) }
    assert_raises(PeriodNotFound) { t_tz.local_to_utc(t) }
    assert_raises(PeriodNotFound) { i_tz.local_to_utc(i) }
  end
  
  def test_local_to_utc_default_dst_set_true
    Timezone.default_dst = true
  
    o1 = TimezoneOffsetInfo.new(-18000, 0, :EST)
    o2 = TimezoneOffsetInfo.new(-18000, 3600, :EDT)
    
    t1 = TimezoneTransitionInfo.new(o2, o1, 1081062000)
    t2 = TimezoneTransitionInfo.new(o1, o2, 1099202400)
    t3 = TimezoneTransitionInfo.new(o2, o1, 1112511600)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(t2, t3)
    
    dt = DateTime.new(2004,10,31,1,30,0)    
    tz = TestTimezone.new('America/New_York', nil, [p1, p2], dt)
    
    assert_equal(DateTime.new(2004,10,31,5,30,0), tz.local_to_utc(dt))    
    assert_equal(DateTime.new(2004,10,31,5,30,0), tz.local_to_utc(dt, true))
    assert_equal(DateTime.new(2004,10,31,6,30,0), tz.local_to_utc(dt, false))
    assert_raises(AmbiguousTime) { tz.local_to_utc(dt, nil) }
    assert_equal(DateTime.new(2004,10,31,5,30,0), tz.local_to_utc(dt) {|periods| raise BlockCalled, 'should not be called' })
  end
  
  def test_local_to_utc_default_dst_set_false
    Timezone.default_dst = false
  
    o1 = TimezoneOffsetInfo.new(-18000, 0, :EST)
    o2 = TimezoneOffsetInfo.new(-18000, 3600, :EDT)
    
    t1 = TimezoneTransitionInfo.new(o2, o1, 1081062000)
    t2 = TimezoneTransitionInfo.new(o1, o2, 1099202400)
    t3 = TimezoneTransitionInfo.new(o2, o1, 1112511600)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(t2, t3)
    
    dt = DateTime.new(2004,10,31,1,30,0)    
    tz = TestTimezone.new('America/New_York', nil, [p1, p2], dt)
        
    assert_equal(DateTime.new(2004,10,31,6,30,0), tz.local_to_utc(dt))
    assert_equal(DateTime.new(2004,10,31,6,30,0), tz.local_to_utc(dt, false))
    assert_equal(DateTime.new(2004,10,31,5,30,0), tz.local_to_utc(dt, true))
    assert_raises(AmbiguousTime) { tz.local_to_utc(dt, nil) }
    assert_equal(DateTime.new(2004,10,31,6,30,0), tz.local_to_utc(dt) {|periods| raise BlockCalled, 'should not be called' })
  end
  
  def test_local_to_utc_dst_flag_resolved
    o1 = TimezoneOffsetInfo.new(-18000, 0, :EST)
    o2 = TimezoneOffsetInfo.new(-18000, 3600, :EDT)
    
    t1 = TimezoneTransitionInfo.new(o2, o1, 1081062000)
    t2 = TimezoneTransitionInfo.new(o1, o2, 1099202400)
    t3 = TimezoneTransitionInfo.new(o2, o1, 1112511600)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(t2, t3)
    
    dt = DateTime.new(2004,10,31,1,30,0)    
    tz = TestTimezone.new('America/New_York', nil, [p1, p2], dt)
        
    assert_equal(DateTime.new(2004,10,31,5,30,0), tz.local_to_utc(dt, true))
    assert_equal(DateTime.new(2004,10,31,6,30,0), tz.local_to_utc(dt, false))
    assert_equal(DateTime.new(2004,10,31,5,30,0), tz.local_to_utc(dt, true) {|periods| raise BlockCalled, 'should not be called' })
    assert_equal(DateTime.new(2004,10,31,6,30,0), tz.local_to_utc(dt, false) {|periods| raise BlockCalled, 'should not be called' })
  end
  
  def test_local_to_utc_dst_block_called
    o1 = TimezoneOffsetInfo.new(-18000, 0, :EST)
    o2 = TimezoneOffsetInfo.new(-18000, 3600, :EDT)
    
    t1 = TimezoneTransitionInfo.new(o2, o1, 1081062000)
    t2 = TimezoneTransitionInfo.new(o1, o2, 1099202400)
    t3 = TimezoneTransitionInfo.new(o2, o1, 1112511600)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(t2, t3)
    
    dt = DateTime.new(2004,10,31,1,30,0)    
    tz = TestTimezone.new('America/New_York', nil, [p1, p2], dt)
    
    assert_raises(BlockCalled) {
      tz.local_to_utc(dt) {|periods|
        assert_equal([p1, p2], periods)                
        
        # raise exception to test that the block was called
        raise BlockCalled, 'should be raised'
      }
    }
    
    assert_equal(DateTime.new(2004,10,31,5,30,0), tz.local_to_utc(dt) {|periods| periods.first})
    assert_equal(DateTime.new(2004,10,31,6,30,0), tz.local_to_utc(dt) {|periods| periods.last})
    assert_equal(DateTime.new(2004,10,31,5,30,0), tz.local_to_utc(dt) {|periods| [periods.first]})
    assert_equal(DateTime.new(2004,10,31,6,30,0), tz.local_to_utc(dt) {|periods| [periods.last]})
  end
  
  def test_local_to_utc_dst_cannot_resolve
    # At midnight local time on Aug 5 1915 in Warsaw, the clocks were put back
    # 24 minutes and both periods were non-DST. Hence the block should be
    # called regardless of the value of the Boolean dst parameter.

    o0 = TimezoneOffsetInfo.new(5040, 0, :LMT)
    o1 = TimezoneOffsetInfo.new(5040, 0, :WMT)
    o2 = TimezoneOffsetInfo.new(3600, 0, :CET)
    o3 = TimezoneOffsetInfo.new(3600, 3600, :CEST)
    
    t1 = TimezoneTransitionInfo.new(o1, o0, 288925853, 120)
    t2 = TimezoneTransitionInfo.new(o2, o1, 290485733, 120)
    t3 = TimezoneTransitionInfo.new(o3, o2, 29051813, 12)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(t2, t3)
    
    dt = DateTime.new(1915,8,4,23,40,0)
    
    tz = TestTimezone.new('Europe/Warsaw', nil, [p1, p2], dt)
        
    assert_raises(BlockCalled) do
      tz.local_to_utc(dt, true) do |periods|
        assert_equal([p1, p2], periods)        
        raise BlockCalled, 'should be raised'
      end
    end
    
    assert_raises(BlockCalled) do
      tz.local_to_utc(dt, false) do |periods|
        assert_equal([p1, p2], periods)        
        raise BlockCalled, 'should be raised'
      end
    end
    
    assert_equal(DateTime.new(1915,8,4,22,16,0), tz.local_to_utc(dt) {|periods| periods.first})
    assert_equal(DateTime.new(1915,8,4,22,40,0), tz.local_to_utc(dt) {|periods| periods.last})
    assert_equal(DateTime.new(1915,8,4,22,16,0), tz.local_to_utc(dt) {|periods| [periods.first]})
    assert_equal(DateTime.new(1915,8,4,22,40,0), tz.local_to_utc(dt) {|periods| [periods.last]})
  end
  
  def test_local_to_utc_block_ambiguous    
    o1 = TimezoneOffsetInfo.new(-18000, 0, :EST)
    o2 = TimezoneOffsetInfo.new(-18000, 3600, :EDT)
    
    t1 = TimezoneTransitionInfo.new(o2, o1, 1081062000)
    t2 = TimezoneTransitionInfo.new(o1, o2, 1099202400)
    t3 = TimezoneTransitionInfo.new(o2, o1, 1112511600)
    
    p1 = TimezonePeriod.new(t1, t2)
    p2 = TimezonePeriod.new(t2, t3)
    
    dt = DateTime.new(2004,10,31,1,30,0)    
    tz = TestTimezone.new('America/New_York', nil, [p1, p2], dt)
    
    dt = DateTime.new(2004,10,31,1,30,0)
    tz = Timezone.get('America/New_York')
    
    assert_raises(AmbiguousTime) { tz.local_to_utc(dt) {|periods| nil} }    
    assert_raises(AmbiguousTime) { tz.local_to_utc(dt) {|periods| periods} }     
    assert_raises(AmbiguousTime) { tz.local_to_utc(dt) {|periods| []} }    
    assert_raises(AmbiguousTime) { tz.local_to_utc(dt) {|periods| raise AmbiguousTime, 'Ambiguous time'} }
  end
  
  def test_now
    assert_kind_of(Time, Timezone.get('Europe/London').now)
  end
  
  def test_current_period
    assert_kind_of(TimezonePeriod, Timezone.get('Europe/London').current_period)
  end
  
  def test_current_period_and_time
    current = Timezone.get('Europe/London').current_period_and_time
    assert_equal(2, current.length)
    assert_kind_of(Time, current[0])
    assert_kind_of(TimezonePeriod, current[1])
  end
  
  def test_current_time_and_period
    current = Timezone.get('Europe/London').current_time_and_period
    assert_equal(2, current.length)
    assert_kind_of(Time, current[0])
    assert_kind_of(TimezonePeriod, current[1])
  end
    
  def test_compare
    assert_equal(0, TestTimezone.new('Europe/London') <=> TestTimezone.new('Europe/London'))
    assert_equal(-1, TestTimezone.new('Europe/London') <=> TestTimezone.new('Europe/london'))
    assert_equal(-1, TestTimezone.new('Europe/London') <=> TestTimezone.new('Europe/Paris'))
    assert_equal(1, TestTimezone.new('Europe/Paris') <=> TestTimezone.new('Europe/London'))
    assert_equal(-1, TestTimezone.new('America/New_York') <=> TestTimezone.new('Europe/Paris'))
    assert_equal(1, TestTimezone.new('Europe/Paris') <=> TestTimezone.new('America/New_York'))    
  end
  
  def test_equality
    assert_equal(true, TestTimezone.new('Europe/London') == TestTimezone.new('Europe/London'))
    assert_equal(false, TestTimezone.new('Europe/London') == TestTimezone.new('Europe/london'))
    assert_equal(false, TestTimezone.new('Europe/London') == TestTimezone.new('Europe/Paris'))
    assert(!(TestTimezone.new('Europe/London') == Object.new))
  end
  
  def test_eql
    assert_equal(true, TestTimezone.new('Europe/London').eql?(TestTimezone.new('Europe/London')))
    assert_equal(false, TestTimezone.new('Europe/London').eql?(TestTimezone.new('Europe/london')))
    assert_equal(false, TestTimezone.new('Europe/London').eql?(TestTimezone.new('Europe/Paris')))
    assert(!TestTimezone.new('Europe/London').eql?(Object.new))
  end
  
  def test_hash
    assert_equal('Europe/London'.hash, TestTimezone.new('Europe/London').hash)
    assert_equal('America/New_York'.hash, TestTimezone.new('America/New_York').hash)
  end
  
  def test_marshal_data
    tz = Timezone.get('Europe/London')
    assert_kind_of(DataTimezone, tz)
    assert_same(tz, Marshal.load(Marshal.dump(tz)))    
  end
  
  def test_marshal_linked
    tz = Timezone.get('UTC')
    assert_kind_of(LinkedTimezone, tz)
    assert_same(tz, Marshal.load(Marshal.dump(tz)))    
  end
  
  def test_strftime_datetime
    tz = Timezone.get('Europe/London')
    assert_equal('23:12:02 BST', tz.strftime('%H:%M:%S %Z', DateTime.new(1965, 7, 15, 22, 12, 2)))
    assert_equal('BST', tz.strftime('%Z', DateTime.new(1965, 7, 15, 22, 12, 2)))
    assert_equal('%ZBST', tz.strftime('%%Z%Z', DateTime.new(1965, 7, 15, 22, 12, 2)))
    assert_equal('BST BST', tz.strftime('%Z %Z', DateTime.new(1965, 7, 15, 22, 12, 2)))
  end
  
  def test_strftime_time
    tz = Timezone.get('Europe/London')
    assert_equal('23:12:02 BST', tz.strftime('%H:%M:%S %Z', Time.utc(2006, 7, 15, 22, 12, 2)))
    assert_equal('BST', tz.strftime('%Z', Time.utc(2006, 7, 15, 22, 12, 2)))
    assert_equal('%ZBST', tz.strftime('%%Z%Z', Time.utc(2006, 7, 15, 22, 12, 2)))
    assert_equal('BST BST', tz.strftime('%Z %Z', Time.utc(2006, 7, 15, 22, 12, 2)))
  end
  
  def test_strftime_int
    tz = Timezone.get('Europe/London')
    assert_equal('23:12:02 BST', tz.strftime('%H:%M:%S %Z', Time.utc(2006, 7, 15, 22, 12, 2).to_i))
    assert_equal('BST', tz.strftime('%Z', Time.utc(2006, 7, 15, 22, 12, 2).to_i))
    assert_equal('%ZBST', tz.strftime('%%Z%Z', Time.utc(2006, 7, 15, 22, 12, 2).to_i))
    assert_equal('BST BST', tz.strftime('%Z %Z', Time.utc(2006, 7, 15, 22, 12, 2).to_i))
  end
end
