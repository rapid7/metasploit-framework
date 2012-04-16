require File.expand_path(File.dirname(__FILE__) + '/../test_helper')

class AutoShop
  attr_accessor :num_customers
  
  def initialize
    @num_customers = 0
    super
  end
  
  state_machine :initial => :available do
    after_transition :available => any, :do => :increment_customers
    after_transition :busy => any, :do => :decrement_customers
    
    event :tow_vehicle do
      transition :available => :busy
    end
    
    event :fix_vehicle do
      transition :busy => :available
    end
  end
  
  # Increments the number of customers in service
  def increment_customers
    self.num_customers += 1
  end
  
  # Decrements the number of customers in service
  def decrement_customers
    self.num_customers -= 1
  end
end

class ModelBase
  def save
    @saved = true
    self
  end
end

class Vehicle < ModelBase
  attr_accessor :auto_shop, :seatbelt_on, :insurance_premium, :force_idle, :callbacks, :saved, :time_elapsed, :last_transition_args
  
  def initialize(attributes = {})
    attributes = {
      :auto_shop => AutoShop.new,
      :seatbelt_on => false,
      :insurance_premium => 50,
      :force_idle => false,
      :callbacks => [],
      :saved => false
    }.merge(attributes)
    
    attributes.each {|attr, value| send("#{attr}=", value)}
    super()
  end
  
  # Defines the state machine for the state of the vehicled
  state_machine :initial => lambda {|vehicle| vehicle.force_idle ? :idling : :parked}, :action => :save do
    before_transition {|vehicle, transition| vehicle.last_transition_args = transition.args}
    before_transition :parked => any, :do => :put_on_seatbelt
    before_transition any => :stalled, :do => :increase_insurance_premium
    after_transition any => :parked, :do => lambda {|vehicle| vehicle.seatbelt_on = false}
    after_transition :on => :crash, :do => :tow
    after_transition :on => :repair, :do => :fix
    
    # Callback tracking for initial state callbacks
    after_transition any => :parked, :do => lambda {|vehicle| vehicle.callbacks << 'before_enter_parked'}
    before_transition any => :idling, :do => lambda {|vehicle| vehicle.callbacks << 'before_enter_idling'}
    
    around_transition do |vehicle, transition, block|
      time = Time.now
      block.call
      vehicle.time_elapsed = Time.now - time
    end
    
    event all do
      transition :locked => :parked
    end
    
    event :park do
      transition [:idling, :first_gear] => :parked
    end
    
    event :ignite do
      transition :stalled => :stalled
      transition :parked => :idling
    end
    
    event :idle do
      transition :first_gear => :idling
    end
    
    event :shift_up do
      transition :idling => :first_gear, :first_gear => :second_gear, :second_gear => :third_gear
    end
    
    event :shift_down do
      transition :third_gear => :second_gear
      transition :second_gear => :first_gear
    end
    
    event :crash do
      transition [:first_gear, :second_gear, :third_gear] => :stalled, :if => lambda {|vehicle| vehicle.auto_shop.available?}
    end
    
    event :repair do
      transition :stalled => :parked, :if => :auto_shop_busy?
    end
  end
  
  state_machine :insurance_state, :initial => :inactive, :namespace => 'insurance' do
    event :buy do
      transition :inactive => :active
    end
    
    event :cancel do
      transition :active => :inactive
    end
  end
  
  def save
    super
  end
  
  def new_record?
    @saved == false
  end
  
  def park
    super
  end
  
  # Tows the vehicle to the auto shop
  def tow
    auto_shop.tow_vehicle
  end
  
  # Fixes the vehicle; it will no longer be in the auto shop
  def fix
    auto_shop.fix_vehicle
  end
  
  def decibels
    0.0
  end
  
  private
    # Safety first! Puts on our seatbelt
    def put_on_seatbelt
      self.seatbelt_on = true
    end
    
    # We crashed! Increase the insurance premium on the vehicle
    def increase_insurance_premium
      self.insurance_premium += 100
    end
    
    # Is the auto shop currently servicing another customer?
    def auto_shop_busy?
      auto_shop.busy?
    end
end

class Car < Vehicle
  state_machine do
    event :reverse do
      transition [:parked, :idling, :first_gear] => :backing_up
    end
    
    event :park do
      transition :backing_up => :parked
    end
    
    event :idle do
      transition :backing_up => :idling
    end
    
    event :shift_up do
      transition :backing_up => :first_gear
    end
  end
end

class Motorcycle < Vehicle
  state_machine :initial => :idling do
    state :first_gear do
      def decibels
        1.0
      end
    end
  end
end

class TrafficLight
  state_machine :initial => :stop do
    event :cycle do
      transition :stop => :proceed, :proceed => :caution, :caution => :stop
    end
    
    state :stop do
      def color(transform)
        value = 'red'
        
        if block_given?
          yield value
        else
          value.send(transform)
        end
        
        value
      end
    end
    
    state all - :proceed do
      def capture_violations?
        true
      end
    end
    
    state :proceed do
      def color(transform)
        'green'
      end

      def capture_violations?
        false
      end
    end
    
    state :caution do
      def color(transform)
        'yellow'
      end
    end
  end
  
  def color(transform = :to_s)
    super
  end
end

class VehicleTest < Test::Unit::TestCase
  def setup
    @vehicle = Vehicle.new
  end
  
  def test_should_not_allow_access_to_subclass_events
    assert !@vehicle.respond_to?(:reverse)
  end
  
  def test_should_have_human_state_names
    assert_equal 'parked', Vehicle.human_state_name(:parked)
  end
  
  def test_should_have_human_state_event_names
    assert_equal 'park', Vehicle.human_state_event_name(:park)
  end
end

class VehicleUnsavedTest < Test::Unit::TestCase
  def setup
    @vehicle = Vehicle.new
  end
  
  def test_should_be_in_parked_state
    assert_equal 'parked', @vehicle.state
  end
  
  def test_should_raise_exception_if_checking_invalid_state
    assert_raise(IndexError) { @vehicle.state?(:invalid) }
  end
  
  def test_should_raise_exception_if_getting_name_of_invalid_state
    @vehicle.state = 'invalid'
    assert_raise(ArgumentError) { @vehicle.state_name }
  end
  
  def test_should_be_parked
    assert @vehicle.parked?
    assert @vehicle.state?(:parked)
    assert_equal :parked, @vehicle.state_name
    assert_equal 'parked', @vehicle.human_state_name
  end
  
  def test_should_not_be_idling
    assert !@vehicle.idling?
  end
  
  def test_should_not_be_first_gear
    assert !@vehicle.first_gear?
  end
  
  def test_should_not_be_second_gear
    assert !@vehicle.second_gear?
  end
  
  def test_should_not_be_stalled
    assert !@vehicle.stalled?
  end
  
  def test_should_not_be_able_to_park
    assert !@vehicle.can_park?
  end
  
  def test_should_not_have_a_transition_for_park
    assert_nil @vehicle.park_transition
  end
  
  def test_should_not_allow_park
    assert !@vehicle.park
  end
  
  def test_should_be_able_to_ignite
    assert @vehicle.can_ignite?
  end
  
  def test_should_have_a_transition_for_ignite
    transition = @vehicle.ignite_transition
    assert_not_nil transition
    assert_equal 'parked', transition.from
    assert_equal 'idling', transition.to
    assert_equal :ignite, transition.event
    assert_equal :state, transition.attribute
    assert_equal @vehicle, transition.object
  end
  
  def test_should_have_a_list_of_possible_events
    assert_equal [:ignite], @vehicle.state_events
  end
  
  def test_should_have_a_list_of_possible_transitions
    assert_equal [{:object => @vehicle, :attribute => :state, :event => :ignite, :from => 'parked', :to => 'idling'}], @vehicle.state_transitions.map {|transition| transition.attributes}
  end
  
  def test_should_have_a_list_of_possible_paths
    assert_equal [[
      StateMachine::Transition.new(@vehicle, Vehicle.state_machine, :ignite, :parked, :idling),
      StateMachine::Transition.new(@vehicle, Vehicle.state_machine, :shift_up, :idling, :first_gear)
    ]], @vehicle.state_paths(:to => :first_gear)
  end
  
  def test_should_allow_generic_event_to_fire
    assert @vehicle.fire_state_event(:ignite)
    assert_equal 'idling', @vehicle.state
  end
  
  def test_should_pass_arguments_through_to_generic_event_runner
    @vehicle.fire_state_event(:ignite, 1, 2, 3)
    assert_equal [1, 2, 3], @vehicle.last_transition_args
  end
  
  def test_should_allow_skipping_action_through_generic_event_runner
    @vehicle.fire_state_event(:ignite, false)
    assert_equal false, @vehicle.saved
  end
  
  def test_should_raise_error_with_invalid_event_through_generic_event_runer
    assert_raise(IndexError) { @vehicle.fire_state_event(:invalid) }
  end
  
  def test_should_allow_ignite
    assert @vehicle.ignite
    assert_equal 'idling', @vehicle.state
  end
  
  def test_should_allow_ignite_with_skipped_action
    assert @vehicle.ignite(false)
    assert @vehicle.new_record?
  end
  
  def test_should_allow_ignite_bang
    assert @vehicle.ignite!
  end
  
  def test_should_allow_ignite_bang_with_skipped_action
    assert @vehicle.ignite!(false)
    assert @vehicle.new_record?
  end
  
  def test_should_be_saved_after_successful_event
    @vehicle.ignite
    assert !@vehicle.new_record?
  end
  
  def test_should_not_allow_idle
    assert !@vehicle.idle
  end
  
  def test_should_not_allow_shift_up
    assert !@vehicle.shift_up
  end
  
  def test_should_not_allow_shift_down
    assert !@vehicle.shift_down
  end
  
  def test_should_not_allow_crash
    assert !@vehicle.crash
  end
  
  def test_should_not_allow_repair
    assert !@vehicle.repair
  end
  
  def test_should_be_insurance_inactive
    assert @vehicle.insurance_inactive?
  end
  
  def test_should_be_able_to_buy
    assert @vehicle.can_buy_insurance?
  end
  
  def test_should_allow_buying_insurance
    assert @vehicle.buy_insurance
  end
  
  def test_should_allow_buying_insurance_bang
    assert @vehicle.buy_insurance!
  end
  
  def test_should_allow_ignite_buying_insurance_with_skipped_action
    assert @vehicle.buy_insurance!(false)
    assert @vehicle.new_record?
  end
  
  def test_should_not_be_insurance_active
    assert !@vehicle.insurance_active?
  end
  
  def test_should_not_be_able_to_cancel
    assert !@vehicle.can_cancel_insurance?
  end
  
  def test_should_not_allow_cancelling_insurance
    assert !@vehicle.cancel_insurance
  end
end

class VehicleParkedTest < Test::Unit::TestCase
  def setup
    @vehicle = Vehicle.new
  end
  
  def test_should_be_in_parked_state
    assert_equal 'parked', @vehicle.state
  end
  
  def test_should_not_have_the_seatbelt_on
    assert !@vehicle.seatbelt_on
  end
  
  def test_should_not_allow_park
    assert !@vehicle.park
  end
  
  def test_should_allow_ignite
    assert @vehicle.ignite
    assert_equal 'idling', @vehicle.state
  end
  
  def test_should_not_allow_idle
    assert !@vehicle.idle
  end
  
  def test_should_not_allow_shift_up
    assert !@vehicle.shift_up
  end
  
  def test_should_not_allow_shift_down
    assert !@vehicle.shift_down
  end
  
  def test_should_not_allow_crash
    assert !@vehicle.crash
  end
  
  def test_should_not_allow_repair
    assert !@vehicle.repair
  end
  
  def test_should_raise_exception_if_repair_not_allowed!
    exception = assert_raise(StateMachine::InvalidTransition) {@vehicle.repair!}
    assert_equal @vehicle, exception.object
    assert_equal Vehicle.state_machine(:state), exception.machine
    assert_equal :repair, exception.event
    assert_equal 'parked', exception.from
  end
end

class VehicleIdlingTest < Test::Unit::TestCase
  def setup
    @vehicle = Vehicle.new
    @vehicle.ignite
  end
  
  def test_should_be_in_idling_state
    assert_equal 'idling', @vehicle.state
  end
  
  def test_should_be_idling
    assert @vehicle.idling?
  end
  
  def test_should_have_seatbelt_on
    assert @vehicle.seatbelt_on
  end
  
  def test_should_track_time_elapsed
    assert_not_nil @vehicle.time_elapsed
  end
  
  def test_should_allow_park
    assert @vehicle.park
  end
  
  def test_should_call_park_with_bang_action
    class << @vehicle
      def park
        super && 1
      end
    end
    
    assert_equal 1, @vehicle.park!
  end
  
  def test_should_not_allow_idle
    assert !@vehicle.idle
  end
  
  def test_should_allow_shift_up
    assert @vehicle.shift_up
  end
  
  def test_should_not_allow_shift_down
    assert !@vehicle.shift_down
  end
  
  def test_should_not_allow_crash
    assert !@vehicle.crash
  end
  
  def test_should_not_allow_repair
    assert !@vehicle.repair
  end
end

class VehicleFirstGearTest < Test::Unit::TestCase
  def setup
    @vehicle = Vehicle.new
    @vehicle.ignite
    @vehicle.shift_up
  end
  
  def test_should_be_in_first_gear_state
    assert_equal 'first_gear', @vehicle.state
  end
  
  def test_should_be_first_gear
    assert @vehicle.first_gear?
  end
  
  def test_should_allow_park
    assert @vehicle.park
  end
  
  def test_should_allow_idle
    assert @vehicle.idle
  end
  
  def test_should_allow_shift_up
    assert @vehicle.shift_up
  end
  
  def test_should_not_allow_shift_down
    assert !@vehicle.shift_down
  end
  
  def test_should_allow_crash
    assert @vehicle.crash
  end
  
  def test_should_not_allow_repair
    assert !@vehicle.repair
  end
end

class VehicleSecondGearTest < Test::Unit::TestCase
  def setup
    @vehicle = Vehicle.new
    @vehicle.ignite
    2.times {@vehicle.shift_up}
  end
  
  def test_should_be_in_second_gear_state
    assert_equal 'second_gear', @vehicle.state
  end
  
  def test_should_be_second_gear
    assert @vehicle.second_gear?
  end
  
  def test_should_not_allow_park
    assert !@vehicle.park
  end
  
  def test_should_not_allow_idle
    assert !@vehicle.idle
  end
  
  def test_should_allow_shift_up
    assert @vehicle.shift_up
  end
  
  def test_should_allow_shift_down
    assert @vehicle.shift_down
  end
  
  def test_should_allow_crash
    assert @vehicle.crash
  end
  
  def test_should_not_allow_repair
    assert !@vehicle.repair
  end
end

class VehicleThirdGearTest < Test::Unit::TestCase
  def setup
    @vehicle = Vehicle.new
    @vehicle.ignite
    3.times {@vehicle.shift_up}
  end
  
  def test_should_be_in_third_gear_state
    assert_equal 'third_gear', @vehicle.state
  end
  
  def test_should_be_third_gear
    assert @vehicle.third_gear?
  end
  
  def test_should_not_allow_park
    assert !@vehicle.park
  end
  
  def test_should_not_allow_idle
    assert !@vehicle.idle
  end
  
  def test_should_not_allow_shift_up
    assert !@vehicle.shift_up
  end
  
  def test_should_allow_shift_down
    assert @vehicle.shift_down
  end
  
  def test_should_allow_crash
    assert @vehicle.crash
  end
  
  def test_should_not_allow_repair
    assert !@vehicle.repair
  end
end

class VehicleStalledTest < Test::Unit::TestCase
  def setup
    @vehicle = Vehicle.new
    @vehicle.ignite
    @vehicle.shift_up
    @vehicle.crash
  end
  
  def test_should_be_in_stalled_state
    assert_equal 'stalled', @vehicle.state
  end
  
  def test_should_be_stalled
    assert @vehicle.stalled?
  end
  
  def test_should_be_towed
    assert @vehicle.auto_shop.busy?
    assert_equal 1, @vehicle.auto_shop.num_customers
  end
  
  def test_should_have_an_increased_insurance_premium
    assert_equal 150, @vehicle.insurance_premium
  end
  
  def test_should_not_allow_park
    assert !@vehicle.park
  end
  
  def test_should_allow_ignite
    assert @vehicle.ignite
  end
  
  def test_should_not_change_state_when_ignited
    assert_equal 'stalled', @vehicle.state
  end
  
  def test_should_not_allow_idle
    assert !@vehicle.idle
  end
  
  def test_should_now_allow_shift_up
    assert !@vehicle.shift_up
  end
  
  def test_should_not_allow_shift_down
    assert !@vehicle.shift_down
  end
  
  def test_should_not_allow_crash
    assert !@vehicle.crash
  end
  
  def test_should_allow_repair_if_auto_shop_is_busy
    assert @vehicle.repair
  end
  
  def test_should_not_allow_repair_if_auto_shop_is_available
    @vehicle.auto_shop.fix_vehicle
    assert !@vehicle.repair
  end
end

class VehicleRepairedTest < Test::Unit::TestCase
  def setup
    @vehicle = Vehicle.new
    @vehicle.ignite
    @vehicle.shift_up
    @vehicle.crash
    @vehicle.repair
  end
  
  def test_should_be_in_parked_state
    assert_equal 'parked', @vehicle.state
  end
  
  def test_should_not_have_a_busy_auto_shop
    assert @vehicle.auto_shop.available?
  end
end

class VehicleLockedTest < Test::Unit::TestCase
  def setup
    @vehicle = Vehicle.new
    @vehicle.state = 'locked'
  end
  
  def test_should_be_parked_after_park
    @vehicle.park
    assert @vehicle.parked?
  end
  
  def test_should_be_parked_after_ignite
    @vehicle.ignite
    assert @vehicle.parked?
  end
  
  def test_should_be_parked_after_shift_up
    @vehicle.shift_up
    assert @vehicle.parked?
  end
  
  def test_should_be_parked_after_shift_down
    @vehicle.shift_down
    assert @vehicle.parked?
  end
end

class VehicleWithParallelEventsTest < Test::Unit::TestCase
  def setup
    @vehicle = Vehicle.new
  end
  
  def test_should_fail_if_any_event_cannot_transition
    assert !@vehicle.fire_events(:ignite, :cancel_insurance)
  end
  
  def test_should_be_successful_if_all_events_transition
    assert @vehicle.fire_events(:ignite, :buy_insurance)
  end
  
  def test_should_not_save_if_skipping_action
    assert @vehicle.fire_events(:ignite, :buy_insurance, false)
    assert !@vehicle.saved
  end
  
  def test_should_raise_exception_if_any_event_cannot_transition_on_bang
    exception = assert_raise(StateMachine::InvalidParallelTransition) { @vehicle.fire_events!(:ignite, :cancel_insurance) }
    assert_equal @vehicle, exception.object
    assert_equal [:ignite, :cancel_insurance], exception.events
  end
  
  def test_should_not_raise_exception_if_all_events_transition_on_bang
    assert @vehicle.fire_events!(:ignite, :buy_insurance)
  end
  
  def test_should_not_save_if_skipping_action_on_bang
    assert @vehicle.fire_events!(:ignite, :buy_insurance, false)
    assert !@vehicle.saved
  end
end

class VehicleWithEventAttributesTest < Test::Unit::TestCase
  def setup
    @vehicle = Vehicle.new
    @vehicle.state_event = 'ignite'
  end
  
  def test_should_fail_if_event_is_invalid
    @vehicle.state_event = 'invalid'
    assert !@vehicle.save
    assert_equal 'parked', @vehicle.state
  end
  
  def test_should_fail_if_event_has_no_transition
    @vehicle.state_event = 'park'
    assert !@vehicle.save
    assert_equal 'parked', @vehicle.state
  end
  
  def test_should_return_original_action_value_on_success
    assert_equal @vehicle, @vehicle.save
  end
  
  def test_should_transition_state_on_success
    @vehicle.save
    assert_equal 'idling', @vehicle.state
  end
end

class MotorcycleTest < Test::Unit::TestCase
  def setup
    @motorcycle = Motorcycle.new
  end
  
  def test_should_be_in_idling_state
    assert_equal 'idling', @motorcycle.state
  end
  
  def test_should_allow_park
    assert @motorcycle.park
  end
  
  def test_should_not_allow_ignite
    assert !@motorcycle.ignite
  end
  
  def test_should_allow_shift_up
    assert @motorcycle.shift_up
  end
  
  def test_should_not_allow_shift_down
    assert !@motorcycle.shift_down
  end
  
  def test_should_not_allow_crash
    assert !@motorcycle.crash
  end
  
  def test_should_not_allow_repair
    assert !@motorcycle.repair
  end
  
  def test_should_inherit_decibels_from_superclass
    @motorcycle.park
    assert_equal 0.0, @motorcycle.decibels
  end
  
  def test_should_use_decibels_defined_in_state
    @motorcycle.shift_up
    assert_equal 1.0, @motorcycle.decibels
  end
end

class CarTest < Test::Unit::TestCase
  def setup
    @car = Car.new
  end
  
  def test_should_be_in_parked_state
    assert_equal 'parked', @car.state
  end
  
  def test_should_not_have_the_seatbelt_on
    assert !@car.seatbelt_on
  end
  
  def test_should_not_allow_park
    assert !@car.park
  end
  
  def test_should_allow_ignite
    assert @car.ignite
    assert_equal 'idling', @car.state
  end
  
  def test_should_not_allow_idle
    assert !@car.idle
  end
  
  def test_should_not_allow_shift_up
    assert !@car.shift_up
  end
  
  def test_should_not_allow_shift_down
    assert !@car.shift_down
  end
  
  def test_should_not_allow_crash
    assert !@car.crash
  end
  
  def test_should_not_allow_repair
    assert !@car.repair
  end
  
  def test_should_allow_reverse
    assert @car.reverse
  end
end

class CarBackingUpTest < Test::Unit::TestCase
  def setup
    @car = Car.new
    @car.reverse
  end
  
  def test_should_be_in_backing_up_state
    assert_equal 'backing_up', @car.state
  end
  
  def test_should_allow_park
    assert @car.park
  end
  
  def test_should_not_allow_ignite
    assert !@car.ignite
  end
  
  def test_should_allow_idle
    assert @car.idle
  end
  
  def test_should_allow_shift_up
    assert @car.shift_up
  end
  
  def test_should_not_allow_shift_down
    assert !@car.shift_down
  end
  
  def test_should_not_allow_crash
    assert !@car.crash
  end
  
  def test_should_not_allow_repair
    assert !@car.repair
  end
  
  def test_should_not_allow_reverse
    assert !@car.reverse
  end
end

class AutoShopAvailableTest < Test::Unit::TestCase
  def setup
    @auto_shop = AutoShop.new
  end
  
  def test_should_be_in_available_state
    assert_equal 'available', @auto_shop.state
  end
  
  def test_should_allow_tow_vehicle
    assert @auto_shop.tow_vehicle
  end
  
  def test_should_not_allow_fix_vehicle
    assert !@auto_shop.fix_vehicle
  end
end

class AutoShopBusyTest < Test::Unit::TestCase
  def setup
    @auto_shop = AutoShop.new
    @auto_shop.tow_vehicle
  end
  
  def test_should_be_in_busy_state
    assert_equal 'busy', @auto_shop.state
  end
  
  def test_should_have_incremented_number_of_customers
    assert_equal 1, @auto_shop.num_customers
  end
  
  def test_should_not_allow_tow_vehicle
    assert !@auto_shop.tow_vehicle
  end
  
  def test_should_allow_fix_vehicle
    assert @auto_shop.fix_vehicle
  end
end

class TrafficLightStopTest < Test::Unit::TestCase
  def setup
    @light = TrafficLight.new
    @light.state = 'stop'
  end
  
  def test_should_use_stop_color
    assert_equal 'red', @light.color
  end
  
  def test_should_pass_arguments_through
    assert_equal 'RED', @light.color(:upcase!)
  end
  
  def test_should_pass_block_through
    color = @light.color {|value| value.upcase!}
    assert_equal 'RED', color
  end
  
  def test_should_use_stop_capture_violations
    assert_equal true, @light.capture_violations?
  end
end

class TrafficLightProceedTest < Test::Unit::TestCase
  def setup
    @light = TrafficLight.new
    @light.state = 'proceed'
  end
  
  def test_should_use_proceed_color
    assert_equal 'green', @light.color
  end
  
  def test_should_use_proceed_capture_violations
    assert_equal false, @light.capture_violations?
  end
end

class TrafficLightCautionTest < Test::Unit::TestCase
  def setup
    @light = TrafficLight.new
    @light.state = 'caution'
  end
  
  def test_should_use_caution_color
    assert_equal 'yellow', @light.color
  end
  
  def test_should_use_caution_capture_violations
    assert_equal true, @light.capture_violations?
  end
end
