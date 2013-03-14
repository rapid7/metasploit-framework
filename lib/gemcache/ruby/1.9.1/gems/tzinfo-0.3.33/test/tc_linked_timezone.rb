$:.unshift File.join(File.dirname(__FILE__), "..", "lib")
require 'test/unit'
require File.join(File.dirname(__FILE__), 'test_utils')
require 'tzinfo'

include TZInfo

class TCLinkedTimezone < Test::Unit::TestCase
  
  class TestTimezone < Timezone
    attr_reader :utc_period
    attr_reader :local_periods
    attr_reader :utc
    attr_reader :local    
    
    def self.new(identifier, no_local_periods = false)
      tz = super()
      tz.send(:setup, identifier, no_local_periods)
      tz
    end
    
    def identifier
      @identifier
    end
    
    def period_for_utc(utc)
      @utc = utc
      @utc_period
    end
    
    def periods_for_local(local)
      @local = local
      raise PeriodNotFound if @no_local_periods
      @local_periods
    end
    
    private
      def setup(identifier, no_local_periods)
        @identifier = identifier
        @no_local_periods = no_local_periods
        
        # Doesn't have to be a real TimezonePeriod (nothing attempts to use it).
        @utc_period = Object.new
        @local_periods = [Object.new, Object.new]
      end
  end
  
  
  def setup
    # Redefine Timezone.get to return a fake timezone.
    # Use without_warnings to suppress redefined get method warning.
    without_warnings do
      def Timezone.get(identifier)
        raise InvalidTimezoneIdentifier, 'Invalid identifier' if identifier == 'Invalid/Identifier'
       
        @timezones ||= {}
        @timezones[identifier] ||= TestTimezone.new(identifier, identifier == 'Test/No/Local')        
      end
    end
  end
  
  def teardown
    # Re-require timezone to reset.
    # Suppress redefined method warnings.
    without_warnings do
      load 'tzinfo/timezone.rb'
    end
  end
  
  def test_identifier
    tz = LinkedTimezone.new(LinkedTimezoneInfo.new('Test/Zone', 'Test/Linked'))
    assert_equal('Test/Zone', tz.identifier)
  end
  
  def test_invalid_linked_identifier
    assert_raises(InvalidTimezoneIdentifier) { LinkedTimezone.new(LinkedTimezoneInfo.new('Test/Zone', 'Invalid/Identifier')) }
  end
  
  def test_period_for_utc
    tz = LinkedTimezone.new(LinkedTimezoneInfo.new('Test/Zone', 'Test/Linked'))
    linked_tz = Timezone.get('Test/Linked')
    t = Time.utc(2006, 6, 27, 23, 12, 28)
    assert_same(linked_tz.utc_period, tz.period_for_utc(t))
    assert_same(t, linked_tz.utc)
  end
  
  def test_periods_for_local
    tz = LinkedTimezone.new(LinkedTimezoneInfo.new('Test/Zone', 'Test/Linked'))
    linked_tz = Timezone.get('Test/Linked')
    t = Time.utc(2006, 6, 27, 23, 12, 28)
    assert_same(linked_tz.local_periods, tz.periods_for_local(t))
    assert_same(t, linked_tz.local)
  end
  
  def test_periods_for_local_not_found
    tz = LinkedTimezone.new(LinkedTimezoneInfo.new('Test/Zone', 'Test/No/Local'))
    linked_tz = Timezone.get('Test/No/Local')
    t = Time.utc(2006, 6, 27, 23, 12, 28)
    assert_raises(PeriodNotFound) { tz.periods_for_local(t) }
    assert_same(t, linked_tz.local)
  end  
end
