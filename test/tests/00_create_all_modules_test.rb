require 'testbase'

describe Msf::Simple::Framework do
  $msf.modules.each_module do |name, mod|
    ref = name
    klass = mod
    it "should be able create #{ref}" do
      e = $msf.modules.create(ref)
    		e.should_not == nil
    end
  end
end
