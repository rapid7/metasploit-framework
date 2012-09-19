module Mail
  class PartsList < Array

    def attachments
      Mail::AttachmentsList.new(self)
    end

    def collect
      if block_given?
        ary = PartsList.new
        each { |o| ary << yield(o) }
        ary
      else
        to_a
      end
    end

    undef :map
    alias_method :map, :collect

    def map!
      raise NoMethodError, "#map! is not defined, please call #collect and create a new PartsList"
    end

    def collect!
      raise NoMethodError, "#collect! is not defined, please call #collect and create a new PartsList"
    end

    def sort
      self.class.new(super)
    end

    def sort!(order)
      sorted = self.sort do |a, b|
        # OK, 10000 is arbitrary... if anyone actually wants to explicitly sort 10000 parts of a
        # single email message... please show me a use case and I'll put more work into this method,
        # in the meantime, it works :)
        get_order_value(a, order) <=> get_order_value(b, order)
      end
      self.clear
      sorted.each { |p| self << p }
    end

  private

    def get_order_value(part, order)
      if part.respond_to?(:content_type)
        order.index(part[:content_type].string.downcase) || 10000
      else
        10000
      end
    end

  end
end
