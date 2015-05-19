# -*- coding: binary -*-

# Rex::Struct2
module Rex
module Struct2

class Restraint

  attr_reader  :max_object, :min_object, :should_update,
    :max_transform, :min_transform, :max_inv_transform, :min_inv_transform
  attr_writer  :max_object, :min_object, :should_update,
    :max_transform, :min_transform, :max_inv_transform, :min_inv_transform


  def initialize(
    max_object=nil, min_object=nil, should_update=false,
    max_transform=nil, min_transform=nil,
    max_inv_transform=nil, min_inv_transform=nil
  )
    @max_object    = max_object
    @min_object    = min_object
    @should_update = should_update

    def_trans = proc {|i| i}

    @max_transform       = max_transform == nil ? def_trans : max_transform
    @min_transform       = min_transform == nil ? def_trans : min_transform
    @max_inv_transform   = max_inv_transform == nil ? def_trans : max_inv_transform
    @min_inv_transform   = min_inv_transform == nil ? def_trans : min_inv_transform
  end

  def min
    return if !min_object
    return min_object.value
  end

  def max
    return if !max_object
    return max_object.value
  end

  # update values if request (ie string set field to its length)
  def update(value)
    return if !@should_update

    max_object.value = max_inv_transform.call(value) if max_object
    min_object.value = min_inv_transform.call(value) if min_object
  end

end

# end Rex::Struct2
end
end
