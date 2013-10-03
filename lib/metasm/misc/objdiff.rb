#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# computes the difference beetween two ruby objects
# walks accessors, arrays and hashes

def Object.diff(o1, o2)
  if o1.class == o2.class
    h = {}
    case o1
    when Array, Hash
      if o1.kind_of? Array
        keys = (0...[o1.length, o2.length].max).to_a
      else
        keys = o1.keys | o2.keys
      end
      keys.each { |k|
        d = diff(o1[k], o2[k])
        h["[#{k.inspect}]"] = d if not d.empty?
      }
    else
      a = (@@diff_accessor_cache ||= {})[o1.class] ||= (im = o1.class.public_instance_methods.grep(/^[a-z]/) ; (im & im.map { |m| m + '=' }).map { |m| m.chop }.find_all { |m| o1.instance_variable_get('@'+m) })
      if a.empty?
        return o1 == o2 ? h : [o1, o2]
      end
      a.each { |k|
        d = diff(o1.send(k), o2.send(k))
        h['.' + k] = d if not d.empty?
      }
    end

    # simplify tree
    h.keys.each { |k|
      if h[k].kind_of? Hash and h[k].length == 1
        v = h.delete k
        h[k + v.keys.first] = v.values.first
      end
    }

    h
  else
    [o1, o2]
  end
end
