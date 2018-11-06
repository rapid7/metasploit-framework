unless String.method_defined? :byteslice
  require 'backports/tools/arguments'

  class String
    def byteslice(start, len = Backports::Undefined)
      # Argument parsing & checking
      if Backports::Undefined == len
        if start.is_a?(Range)
          range = start
          start = Backports.coerce_to_int(range.begin)
          start += bytesize if start < 0
          last = Backports.coerce_to_int(range.end)
          last += bytesize if last < 0
          last += 1 unless range.exclude_end?
          len = last - start
        else
          start = Backports.coerce_to_int(start)
          start += bytesize if start < 0
          len = 1
          return if start >= bytesize
        end
      else
        start = Backports.coerce_to_int(start)
        start += bytesize if start < 0
        len = Backports.coerce_to_int(len)
        return if len < 0
      end
      return if start < 0 || start > bytesize
      len = 0 if len < 0
      # Actual implementation:
      str = unpack("@#{start}a#{len}").first
      str = dup.replace(str) unless self.instance_of?(String) # Must return subclass
      str.force_encoding(encoding) if respond_to?(:encoding)
      str
    end
  end
end
