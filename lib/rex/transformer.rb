# -*- coding: binary -*-
module Rex

###
#
# Transformer - more than meets the eye!
#
# This class, aside from having a kickass name, is responsible for translating
# object instances of one or more types into a single list instance of one or
# more types.  This is useful for translating object instances that be can
# either strings or an array of strings into an array of strings, for
# instance.  It lets you make things take a uniform structure in an abstract
# manner.
#
###
class Transformer

  #
  # Translates the object instance supplied in src_instance to an instance of
  # dst_class.  The dst_class parameter's instance must support the <<
  # operator.  An example call to this method looks something like:
  #
  # Transformer.transform(string, Array, [ String ], target)
  #
  def Transformer.transform(src_instance, dst_class, supported_classes,
      target = nil)
    dst_instance = dst_class.new

    if (src_instance.kind_of?(Array))
      src_instance.each { |src_inst|
        Transformer.transform_single(src_inst, dst_instance,
            supported_classes, target)
      }
    elsif (!src_instance.kind_of?(NilClass))
      Transformer.transform_single(src_instance, dst_instance,
          supported_classes, target)
    end

    return dst_instance
  end

protected

  #
  # Transform a single source instance.
  #
  def Transformer.transform_single(src_instance, dst_instance,
      supported_classes, target)
    # If the src instance's class is supported, just add it to the dst
    # instance
    if (supported_classes.include?(src_instance.class))
      dst_instance << src_instance
    # If the src instance's class is an array, then we should check to see
    # if any of the supporting classes support from_a.
    elsif (src_instance.kind_of?(Array))
      new_src_instance = nil

      # Walk each supported class calling from_a if exported
      supported_classes.each { |sup_class|
        next if (sup_class.respond_to?('from_a') == false)

        new_src_instance = sup_class.from_a(src_instance)

        if (new_src_instance != nil)
          dst_instance << new_src_instance
          break
        end
      }

      # If we don't have a valid new src instance, then we suck
      if (new_src_instance == nil)
        bomb_translation(src_instance, target)
      end

    # If the source instance is a string, query each of the supported
    # classes to see if they can serialize it to their particular data
    # type.
    elsif (src_instance.kind_of?(String))
      new_src_instance = nil

      # Walk each supported class calling from_s if exported
      supported_classes.each { |sup_class|
        next if (sup_class.respond_to?('from_s') == false)

        new_src_instance = sup_class.from_s(src_instance)

        if (new_src_instance != nil)
          dst_instance << new_src_instance
          break
        end
      }

      # If we don't have a valid new src instance, then we suck
      if (new_src_instance == nil)
        bomb_translation(src_instance, target)
      end
    # Otherwise, bomb translation
    else
      bomb_translation(src_instance, target)
    end
  end

  def Transformer.bomb_translation(src_instance, target) # :nodoc:
    error = "Invalid source class (#{src_instance.class})"

    if (target != nil)
      error += " for #{target}"
    end

    raise ArgumentError, error, caller
  end

end

end

