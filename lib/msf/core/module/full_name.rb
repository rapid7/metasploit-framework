# Names that derive from `Mdm::Module::Class#full_name`.
module Msf::Module::FullName
  extend ActiveSupport::Concern

  module ClassMethods
    # (see #full_name)
    # @deprecated Use {#full_name}.
    def fullname
      ActiveSupport::Deprecation.warn "#{self}.#{__method__} is deprecated.  Use #{self}.full_name instead"
      full_name
    end

    # The module's full name, including its module_type and {#reference_name}.
    #
    # @return [String] '<module_type>/<{#reference_name}>'.
    def full_name
      # cache the value to limit the trips to the database
      @full_name ||= module_class.full_name
    end

    # (see #refname)
    # @deprecated Use {#reference_name}
    def refname
      ActiveSupport::Deprecation.warn "#{self}.#{__method__} is deprecated.  Use #{self}.reference_name instead"
      reference_name
    end

    # The name of the module scoped to the module type.
    #
    # @return [String]
    def reference_name
      # cache the value to limit the trips to the database
      @reference_name ||= module_class.reference_name
    end

    # (see #short_name)
    # @deprecated Use {#short_name}
    def shortname
      ActiveSupport::Deprecation.warn "#{self}.#{__method__} is deprecated.  Use #{self}.short_name instead"
      short_name
    end

    # The last name in the {#reference_name}.  Use along with the module type in the console and other UI locations
    # where the {#full_name} would be too long.
    #
    # @return [String]
    def short_name
      @short_name ||= reference_name.split('/')[-1]
    end
  end

  #
  # Instance Methods
  #

  # @!method full_name
  #   (see Msf::Module::FullName::ClassMethods#full_name)
  #
  # @!method reference_name
  #   (see Msf::Module::FullName::ClassMethods#reference_name)
  #
  # @!method short_name
  #   (see Msf::Module::FullName::ClassMethods#short_name)
  delegate :full_name,
           :reference_name,
           :short_name,
           to: 'self.class'

  # (see Msf::Module::FullName::ClassMethods#full_name)
  # @deprecated (Use #full_name)
  def fullname
    ActiveSupport::Deprecation.warn "#{self.class}##{__method__} is deprecated.  Use #{self.class}#full_name instead"
    full_name
  end

  # (see Msf::Module::FullName::ClassMethods#reference_name)
  # @deprecated
  def refname
    ActiveSupport::Deprecation.warn "#{self.class}##{__method__} is deprecated.  Use #{self.class}#reference_name instead"
    reference_name
  end

  # (see Msf::Module::FullName::ClassMethods#short_name)
  # @deprecated Use {#short_name}
  def shortname
    ActiveSupport::Deprecation.warn "#{self.class}##{__method__} is deprecated.  Use #{self.class}#short_name instead"
    short_name
  end
end
