XDR::RPC::Record = Struct.new(:last, :length, :content)

XDR::RPC::Record.class_eval do
  def last?
    self.last
  end
end