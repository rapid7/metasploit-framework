class XDR::Enum
  extend XDR::Concerns::ConvertsToXDR
  extend XDR::DSL::Enum

  class_attribute :members
  class_attribute :by_value
  class_attribute :sealed
  self.members = ActiveSupport::OrderedHash.new.with_indifferent_access
  self.by_value = ActiveSupport::OrderedHash.new
  self.sealed  = false

  def self.write(val, io)
    raise XDR::WriteError, "Invalid enum value: #{val.inspect}" unless val.is_a?(self)

    XDR::Int.write(val.value, io)
  end

  def self.read(io)
    value = XDR::Int.read(io)
    by_value[value].tap do |result|
      raise XDR::EnumValueError, "Unknown #{name} member: #{value}" if result.blank?
    end
  end
  
  def self.valid?(val)
    val.is_a?(self)
  end

  def self.from_name(name)
    normalized = name.to_s.underscore
    members[normalized].tap do |r|      
      raise XDR::EnumNameError, "#{name} is not a member of #{self.name}" if r.blank?
    end
  end

  attr_reader :name
  attr_reader :value

  def initialize(name, value)
    raise ArgumentError, "#{self.class} is sealed" if self.sealed
    @name  = name
    @value = value
  end

  def to_s
    "#{self.class.name}.#{@name}(#{@value})"
  end
end