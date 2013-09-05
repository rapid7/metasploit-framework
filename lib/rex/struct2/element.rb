#!/usr/bin/env ruby
# -*- coding: binary -*-

# Rex::Struct2
module Rex
module Struct2

module Element

  # elements should have to_s, but we don't define it here because
  # it will just overlap with inheritence and cause issues

  attr_reader  :value, :restraint, :container
  attr_writer  :restraint, :container

  # update the restraints on any value change
  def value=(newval)
    @value = newval
    self.update_restraint
  end

  # avoid conflicting with normal namespace length()
  def slength
    to_s().length()
  end

  def update_restraint
    if self.restraint
      # Sort of a hack, but remove the restraint before we update, so we aren't using
      # the old restraint during calculating the restraint update value
      old_restraint, self.restraint = self.restraint, nil
      old_restraint.update(self.slength)
      self.restraint = old_restraint
    end

    if self.container
      self.container.update_restraint
    end
  end

end

# end Rex::Struct2
end
end
