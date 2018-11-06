# frozen_string_literal: true
class Module
  # Returns the class name of a full module namespace path
  #
  # @example
  #   module A::B::C; class_name end # => "C"
  # @return [String] the last part of a module path
  def class_name
    name.split("::").last
  end

  # Returns the module namespace path minus the class/module name
  #
  # @example
  #   module A::B::C; namespace_name end # => "A::B"
  # @return [String] the namespace minus the class/module name
  def namespace_name
    name.split("::")[0..-2].join("::")
  end
end
