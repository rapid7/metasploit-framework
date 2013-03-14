require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')

describe Thor::Shell::HTML do
  def shell
    @shell ||= Thor::Shell::HTML.new
  end

  describe "#say" do
    it "set the color if specified" do
      out = capture(:stdout) { shell.say "Wow! Now we have colors!", :green }
      out.chomp.should == '<span style="color: green;">Wow! Now we have colors!</span>'
    end

    it "sets bold if specified" do
      out = capture(:stdout) { shell.say "Wow! Now we have colors *and* bold!", [:green, :bold] }
      out.chomp.should == '<span style="color: green; font-weight: bold;">Wow! Now we have colors *and* bold!</span>'
    end

    it "does not use a new line even with colors" do
      out = capture(:stdout) { shell.say "Wow! Now we have colors! ", :green }
      out.chomp.should == '<span style="color: green;">Wow! Now we have colors! </span>'
    end
  end

  describe "#say_status" do
    it "uses color to say status" do
      $stdout.should_receive(:puts).with('<span style="color: red; font-weight: bold;">    conflict</span>  README')
      shell.say_status :conflict, "README", :red
    end
  end

end
