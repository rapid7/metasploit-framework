require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')

describe Thor::Shell::Color do
  def shell
    @shell ||= Thor::Shell::Color.new
  end

  describe "#say" do
    it "set the color if specified" do
      $stdout.should_receive(:puts).with("\e[32mWow! Now we have colors!\e[0m")
      shell.say "Wow! Now we have colors!", :green
    end

    it "does not use a new line even with colors" do
      $stdout.should_receive(:print).with("\e[32mWow! Now we have colors! \e[0m")
      shell.say "Wow! Now we have colors! ", :green
    end
  end

  describe "#say_status" do
    it "uses color to say status" do
      $stdout.should_receive(:puts).with("\e[1m\e[31m    conflict\e[0m  README")
      shell.say_status :conflict, "README", :red
    end
  end

  describe "#file_collision" do
    describe "when a block is given" do
      it "invokes the diff command" do
        $stdout.stub!(:print)
        $stdin.should_receive(:gets).and_return('d')
        $stdin.should_receive(:gets).and_return('n')

        output = capture(:stdout){ shell.file_collision('spec/fixtures/doc/README'){ "README\nEND\n" } }
        output.should =~ /\e\[31m\- __start__\e\[0m/
        output.should =~ /^  README/
        output.should =~ /\e\[32m\+ END\e\[0m/
      end
    end
  end
end
