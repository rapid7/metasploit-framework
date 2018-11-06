# frozen_string_literal: true
module YARD::CodeObjects
  register_separator NSEP, :module

  # Represents a Ruby module.
  class ModuleObject < NamespaceObject
    # Returns the inheritance tree of mixins.
    #
    # @param [Boolean] include_mods if true, will include mixed in
    #   modules (which is likely what is wanted).
    # @return [Array<NamespaceObject>] a list of namespace objects
    def inheritance_tree(include_mods = false)
      return [self] unless include_mods
      [self] + mixins(:instance, :class).map do |m|
        next if m == self
        next m unless m.respond_to?(:inheritance_tree)
        m.inheritance_tree(true)
      end.compact.flatten.uniq
    end
  end
end
