require 'weakref'

module Metasploit::Framework::ResurrectingAttribute
  def resurrecting_attr_accessor(attribute_name, &block)
    instance_variable_name = "@#{attribute_name}".to_sym
    getter_name = attribute_name
    setter_name = "#{attribute_name}="

    define_method(getter_name) do
      begin
        strong_reference = nil
        weak_reference = instance_variable_get instance_variable_name

        if weak_reference
          strong_reference = weak_reference.__getobj__
        else
          strong_reference = instance_exec(&block)

          send(setter_name, strong_reference)
        end
      rescue WeakRef::RefError
        # try again by rebuild because __getobj__ failed on the weak_reference because the referenced object was garbage
        # collected.
        instance_variable_set instance_variable_name, nil

        retry
      end

      # Return strong reference so consuming code doesn't have to handle the weak_reference being garbase collected.
      strong_reference
    end

    define_method(setter_name) do |strong_reference|
      unless strong_reference.nil?
        weak_reference = WeakRef.new(strong_reference)
      else
        weak_reference = strong_reference
      end

      instance_variable_set instance_variable_name, weak_reference

      # don't return the WeakRef as the use of WeakRefs is an implementation detail and __getobj__ failure hiding is the
      # purpose of the reader.
      strong_reference
    end
  end
end
