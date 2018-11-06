require 'spec_helper'

PacketFu.packet_classes.each do |pclass|
  describe pclass, "peek format" do
    it "will display sensible peek information" do
      p = pclass.new
      p.respond_to?(:peek).should be true
      p.peek.size.should be <= 80, p.peek.inspect
      p.peek.should match(/^[A-Z0-9?]../)
    end
  end
end
