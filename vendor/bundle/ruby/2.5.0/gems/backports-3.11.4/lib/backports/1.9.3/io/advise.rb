unless IO.method_defined? :advise
  require 'backports/tools/arguments'

  class IO
    def advise(advice, offset=0, len=0)
      raise RangeError if Backports.coerce_to_int(offset) >= 1<<31
      raise RangeError if Backports.coerce_to_int(len) >= 1<<31
      raise IOError if closed?
      case advice
      when  :normal,
            :sequential,
            :random,
            :willneed,
            :dontneed,
            :noreuse
        return nil
      when Symbol
        raise NotImplementedError, "Unsupported advice #{advice}"
      else
        raise TypeError, "advice must be a Symbol"
      end
    end
  end
end
