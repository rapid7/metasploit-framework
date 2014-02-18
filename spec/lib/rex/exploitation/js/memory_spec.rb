require 'rex/exploitation/js'

describe Rex::Exploitation::Js::Memory do

  context "Class methods" do

    context ".mstime_malloc" do
      it "should load the mstime_malloc javascript" do
        js = Rex::Exploitation::Js::Memory.mstime_malloc
        js.should =~ /function mstime_malloc/
      end
    end

    context ".property_spray" do
      it "should load the property_spray javascript" do
        js = Rex::Exploitation::Js::Memory.property_spray
        js.should =~ /function sprayHeap/
      end
    end

    context ".heap_spray" do
      it "should load the heap_spray javascript" do
        js = Rex::Exploitation::Js::Memory.heap_spray
        js.should =~ /function sprayHeap/
      end
    end

  end

end