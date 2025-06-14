# -*- coding: binary -*-

module Msf::Module::Deprecated

  # Additional class methods for deprecated modules
  module ClassMethods
    attr_accessor :deprecation_date
    attr_accessor :deprecated_names
    attr_accessor :deprecation_reason

    # Mark this module as deprecated
    #
    # Any time this module is run it will print warnings to that effect.
    #
    # @param date [Date,#to_s] The date on which this module will
    #   be removed
    # @param reason [String] A description reason for this module being deprecated
    # @return [void]
    def deprecated(date = nil, reason = nil)
      self.deprecation_date = date
      self.deprecation_reason = reason

      # NOTE: fullname isn't set until a module has been added to a set, which is after it is evaluated
      add_warning do
        details = [
          "*%red" + "The module #{fullname} is deprecated!".center(88) + "%clr*",
        ]
        details << "*" + "This module will be removed on or about #{date}".center(88) + "*" if date
        details << "*#{reason.center(88)}*" if reason.present?

        details
      end
    end

    # Mark this module as moved from another location. This adds an alias to
    # the module so that it can still be used by its old name and will print a
    # warning informing the use of the new name.
    #
    # @param from [String] the previous `fullname` of the module
    def moved_from(from)
      self.deprecated_names << from

      if const_defined?(:Aliases)
        const_get(:Aliases).append from
      else
        const_set(:Aliases, [from])
      end

      # NOTE: aliases are not set until after initialization, so might as well
      # use the block form of alert here too.
      add_warning do
        if fullname == from
          [ "*%red" + "The module #{fullname} has been moved!".center(88) + "%clr*",
            "*" + "You are using #{realname}".center(88) + "*" ]
        end
      end
    end
  end

  # Extends with {ClassMethods}
  def self.included(base)
    base.extend(ClassMethods)
    base.deprecated_names = []
  end
end
