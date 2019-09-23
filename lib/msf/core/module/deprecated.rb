# -*- coding: binary -*-

module Msf::Module::Deprecated

  # Additional class methods for deprecated modules
  module ClassMethods
    attr_accessor :deprecation_date
    attr_accessor :deprecated_name

    # Mark this module as deprecated
    #
    # Any time this module is run it will print warnings to that effect.
    #
    # @param deprecation_date [Date,#to_s] The date on which this module will
    #   be removed
    # @return [void]
    def deprecated(date)
      self.deprecation_date = date

      # NOTE: fullname isn't set until a module has been added to a set, which is after it is evaluated
      add_warning do
        [ "*%red" + "The module #{fullname} is deprecated!".center(88) + "%clr*",
          "*" + "This module will be removed on or about #{self.class.deprecation_date}".center(88) + "*" ]
      end
    end

    # Mark this module as moved from another location. This adds an alias to
    # the module so that it can still be used by its old name and will print a
    # warning informing the use of the new name. This currently only works for
    # a single move, but it can be extended in the future for multiple moves.
    #
    # @param from [String] the previous `fullname` of the module
    def moved_from(from)
      self.deprecated_name = from

      if const_defined?(:Aliases)
        const_get(:Aliases).append from
      else
        const_set(:Aliases, [from])
      end

      # NOTE: aliases are not set until after initialization, so might as well
      # use the block form of alert here too.
      add_warning do
        if fullname == self.class.deprecated_name
          [ "*%red" + "The module #{fullname} has been moved!".center(88) + "%clr*",
            "*" + "You are now using #{realname}".center(88) + "*" ]
        end
      end
    end
  end

  # Extends with {ClassMethods}
  def self.included(base)
    base.extend(ClassMethods)
  end
end
