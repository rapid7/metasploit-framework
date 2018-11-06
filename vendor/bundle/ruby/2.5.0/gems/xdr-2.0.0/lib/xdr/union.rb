class XDR::Union
  include ActiveModel::Model
  include ActiveModel::AttributeMethods

  extend XDR::Concerns::ConvertsToXDR
  extend XDR::DSL::Union


  class_attribute :arms
  class_attribute :switches
  class_attribute :switch_type
  class_attribute :switch_name
  attr_reader     :switch
  attr_reader     :arm

  self.arms        = ActiveSupport::OrderedHash.new
  self.switches    = ActiveSupport::OrderedHash.new
  self.switch_type = nil
  self.switch_name = nil

  attribute_method_suffix '!'

  def self.arm_for_switch(switch)
    begin
      switch = normalize_switch switch
    rescue ArgumentError => e
      raise XDR::InvalidSwitchError, e.message
    end

    result = switches.fetch(switch, :switch_not_found)
    result = switches.fetch(:default, :switch_not_found) if result == :switch_not_found

    if result == :switch_not_found
      raise XDR::InvalidSwitchError, "Bad switch: #{switch}"
    end

    result
  end

  def self.normalize_switch(switch)
    case
    when switch.is_a?(self.switch_type)
      switch
    when self.switch_type.valid?(switch)
      switch
    when self.switch_type.respond_to?(:from_name)
      self.switch_type.from_name(switch)
    else
      raise ArgumentError, "Cannot normalize switch: #{switch.inspect} to type: #{self.switch_type}"
    end
  end

  def self.read(io)
    switch   = switch_type.read(io)
    arm      = arm_for_switch(switch)
    arm_type = arms[arm] || XDR::Void
    value    = arm_type.read(io)
    new(switch, value)
  end

  def self.write(val, io)
    switch_type.write(val.switch, io)
    arm_type = arms[val.arm] || XDR::Void
    arm_type.write(val.get,io)
  end

  def self.valid?(val)
    val.is_a?(self)
  end

  def initialize(switch=:__unset__, value=:void)
    @switch   = nil
    @arm      = nil
    @value    = nil
    set(switch, value) unless switch == :__unset__
  end

  def to_xdr
    self.class.to_xdr self
  end

  def set(switch, value=:void)
    @switch = self.class.normalize_switch switch
    @arm    = self.class.arm_for_switch @switch

    raise XDR::InvalidValueError unless valid_for_arm_type(value, @arm)

    @value = value
  rescue XDR::EnumNameError
    raise XDR::InvalidSwitchError, "Bad switch: #{switch}"
  end

  def value
    @value unless @value == :void
  end

  alias get value

  def attribute!(attr)
    if @arm.to_s != attr
      raise XDR::ArmNotSetError, "#{attr} is not the set arm"
    end

    get
  end


  #
  # Compares two unions for equality
  #
  def == (other)
    return false unless other.is_a?(self.class)
    return false unless other.switch == self.switch
    other.value == self.value
  end

  def eql?(other)
    return false unless other.is_a?(self.class)
    return false unless other.switch.eql? self.switch
    other.value.eql? self.value
  end
  
  def hash
    [self.class, self.switch, self.value].hash
  end

  private
  def valid_for_arm_type(value, arm)
    arm_type = arms[@arm]

    return value == :void if arm_type.nil?

    arm_type.valid?(value)
  end
end
