module XDR::DSL::Enum

  def member(name, value)
    raise ArgumentError, "#{self} is sealed" if self.sealed
    raise ArgumentError, "#{value} is not Integer" unless value.is_a?(Integer)
    raise ArgumentError, "#{value} is already used" unless 

    name = name.to_s.underscore

    instance = new(name, value)
    self.members = self.members.merge(name => instance)
    self.by_value = self.by_value.merge(instance.value => instance)

    class_eval <<-EOS, __FILE__, __LINE__
      def self.#{name}
        members["#{name}"]
      end
    EOS
  end

  def seal
    self.sealed = true
  end
end