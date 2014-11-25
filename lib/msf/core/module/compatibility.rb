module Msf::Module::Compatibility
  #
  # Returns the hash that describes this module's compatibilities.
  #
  def compat
    module_info['Compat'] || {}
  end

  #
  # Returns whether or not this module is compatible with the supplied
  # module.
  #
  def compatible?(mod)
    ch = nil

    # Invalid module?  Shoot, we can't compare that.
    return true if (mod == nil)

    # Determine which hash to used based on the supplied module type
    if (mod.type == Msf::MODULE_ENCODER)
      ch = self.compat['Encoder']
    elsif (mod.type == Msf::MODULE_NOP)
      ch = self.compat['Nop']
    elsif (mod.type == Msf::MODULE_PAYLOAD)
      ch = self.compat['Payload']
      if self.respond_to?("target") and self.target and self.target['Payload'] and self.target['Payload']['Compat']
        ch = ch.merge(self.target['Payload']['Compat'])
      end
    else
      return true
    end

    # Enumerate each compatibility item in our hash to find out
    # if we're compatible with this sucker.
    ch.each_pair do |k,v|

      # Get the value of the current key from the module, such as
      # the ConnectionType for a stager (ws2ord, for instance).
      mval = mod.module_info[k]

      # Reject a filled compat item on one side, but not the other
      if (v and not mval)
        dlog("Module #{mod.refname} is incompatible with #{self.refname} for #{k}: limiter was #{v}")
        return false
      end

      # Track how many of our values matched the module
      mcnt = 0

      # Values are whitespace separated
      sv = v.split(/\s+/)
      mv = mval.split(/\s+/)

      sv.each do |x|

        dlog("Checking compat [#{mod.refname} with #{self.refname}]: #{x} to #{mv.join(", ")}", 'core', LEV_3)

        # Verify that any negate values are not matched
        if (x[0,1] == '-' and mv.include?(x[1, x.length-1]))
          dlog("Module #{mod.refname} is incompatible with #{self.refname} for #{k}: limiter was #{x}, value was #{mval}", 'core', LEV_1)
          return false
        end

        mcnt += 1 if mv.include?(x)
      end

      # No values matched, reject this module
      if (mcnt == 0)
        dlog("Module #{mod.refname} is incompatible with #{self.refname} for #{k}: limiter was #{v}, value was #{mval}", 'core', LEV_1)
        return false
      end

    end

    dlog("Module #{mod.refname} is compatible with #{self.refname}", "core", LEV_1)


    # If we get here, we're compatible.
    return true
  end

  protected

  #
  # This method initializes the module's compatibility hashes by normalizing
  # them into one single hash.  As it stands, modules can define
  # compatibility in their supplied info hash through:
  #
  # Compat::        direct compat definitions
  # PayloadCompat:: payload compatibilities
  # EncoderCompat:: encoder compatibilities
  # NopCompat::     nop compatibilities
  #
  # In the end, the module specific compatibilities are merged as sub-hashes
  # of the primary Compat hash key to make checks more uniform.
  #
  def init_compat
    c = module_info['Compat']

    if (c == nil)
      c = module_info['Compat'] = Hash.new
    end

    # Initialize the module sub compatibilities
    c['Payload'] = Hash.new if (c['Payload'] == nil)
    c['Encoder'] = Hash.new if (c['Encoder'] == nil)
    c['Nop']     = Hash.new if (c['Nop'] == nil)

    # Update the compat-derived module specific compatibilities from
    # the specific ones to make a uniform view of compatibilities
    c['Payload'].update(module_info['PayloadCompat'] || {})
    c['Encoder'].update(module_info['EncoderCompat'] || {})
    c['Nop'].update(module_info['NopCompat'] || {})
  end
end