require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe Thor::Shell do
  def shell
    @shell ||= Thor::Base.shell.new
  end

  describe "#initialize" do
    it "sets shell value" do
      base = MyCounter.new [1, 2], { }, :shell => shell
      base.shell.should == shell
    end

    it "sets the base value on the shell if an accessor is available" do
      base = MyCounter.new [1, 2], { }, :shell => shell
      shell.base.should == base
    end
  end

  describe "#shell" do
    it "returns the shell in use" do
      MyCounter.new([1,2]).shell.should be_kind_of(Thor::Base.shell)
    end

    it "uses $THOR_SHELL" do
      class Thor::Shell::TestShell < Thor::Shell::Basic; end

      Thor::Base.shell.should == shell.class
      ENV['THOR_SHELL'] = 'TestShell'
      Thor::Base.shell = nil
      Thor::Base.shell.should == Thor::Shell::TestShell
      ENV['THOR_SHELL'] = ''
      Thor::Base.shell = shell.class
      Thor::Base.shell.should == shell.class
    end
  end

  describe "with_padding" do
    it "uses padding for inside block outputs" do
      base = MyCounter.new([1,2])
      base.with_padding do
        capture(:stdout){ base.say_status :padding, "cool" }.strip.should == "padding    cool"
      end
    end
  end

end
