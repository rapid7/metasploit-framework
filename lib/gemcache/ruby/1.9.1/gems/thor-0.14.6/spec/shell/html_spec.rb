require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')

describe Thor::Shell::HTML do
  def shell
    @shell ||= Thor::Shell::HTML.new
  end

  describe "#say" do
    it "set the color if specified" do
      $stdout.should_receive(:puts).with('<span style="color: green;">Wow! Now we have colors!</span>')
      shell.say "Wow! Now we have colors!", :green
    end

    it "does not use a new line even with colors" do
      $stdout.should_receive(:print).with('<span style="color: green;">Wow! Now we have colors! </span>')
      shell.say "Wow! Now we have colors! ", :green
    end
  end

  describe "#say_status" do
    it "uses color to say status" do
      $stdout.should_receive(:puts).with('<strong><span style="color: red;">    conflict</span></strong>  README')
      shell.say_status :conflict, "README", :red
    end
  end

end
