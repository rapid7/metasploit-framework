module IPAddrExtensions
  extend ActiveSupport::Concern
  included do
    alias_method_chain :coerce_other, :rescue
  end
  
  def coerce_other_with_rescue(other)
    begin
      case other
      when IPAddr
        other
      when String
        self.class.new(other)
      else
        self.class.new(other, @family)
      end
    rescue ArgumentError => e
      OpenStruct.new(family: false, to_i: false)
    end
  end
  
end

IPAddr.send(:include, IPAddrExtensions)