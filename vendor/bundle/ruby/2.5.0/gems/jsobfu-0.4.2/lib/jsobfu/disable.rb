#
# Behavior for disabling JSObfu during spec runs
#
module JSObfu::Disable

  module ClassMethods
    # Set up some class variables for allowing specs
    @@lock = Mutex.new
    @@disabled = false

    # Globally enable or disable obfuscation, useful for unit tests etc
    # @param val [Boolean] the global obfuscation state to set
    def disabled=(val)
      @@lock.synchronize { @@disabled = val }
    end

    # @return [Boolean] obfuscation is globally disabled
    def disabled?
      @@disabled
    end
  end

  def self.included(base)
    base.extend(ClassMethods)
  end

end
