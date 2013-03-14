require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')
require 'thor/actions'

describe Thor::Actions::CreateFile do
  before do
    ::FileUtils.rm_rf(destination_root)
  end

  def create_file(destination=nil, config={}, options={})
    @base = MyCounter.new([1,2], options, { :destination_root => destination_root })
    @base.stub!(:file_name).and_return('rdoc')

    @action = Thor::Actions::CreateFile.new(@base, destination, "CONFIGURATION",
                                            { :verbose => !@silence }.merge(config))
  end

  def invoke!
    capture(:stdout){ @action.invoke! }
  end

  def revoke!
    capture(:stdout){ @action.revoke! }
  end

  def silence!
    @silence = true
  end

  describe "#invoke!" do
    it "creates a file" do
      create_file("doc/config.rb")
      invoke!
      File.exists?(File.join(destination_root, "doc/config.rb")).should be_true
    end

    it "does not create a file if pretending" do
      create_file("doc/config.rb", {}, :pretend => true)
      invoke!
      File.exists?(File.join(destination_root, "doc/config.rb")).should be_false
    end

    it "shows created status to the user" do
      create_file("doc/config.rb")
      invoke!.should == "      create  doc/config.rb\n"
    end

    it "does not show any information if log status is false" do
      silence!
      create_file("doc/config.rb")
      invoke!.should be_empty
    end

    it "returns the given destination" do
      capture(:stdout) do
        create_file("doc/config.rb").invoke!.should == "doc/config.rb"
      end
    end

    it "converts encoded instructions" do
      create_file("doc/%file_name%.rb.tt")
      invoke!
      File.exists?(File.join(destination_root, "doc/rdoc.rb.tt")).should be_true
    end

    describe "when file exists" do
      before do
        create_file("doc/config.rb")
        invoke!
      end

      describe "and is identical" do
        it "shows identical status" do
          create_file("doc/config.rb")
          invoke!
          invoke!.should == "   identical  doc/config.rb\n"
        end
      end

      describe "and is not identical" do
        before do
          File.open(File.join(destination_root, 'doc/config.rb'), 'w'){ |f| f.write("FOO = 3") }
        end

        it "shows forced status to the user if force is given" do
          create_file("doc/config.rb", {}, :force => true).should_not be_identical
          invoke!.should == "       force  doc/config.rb\n"
        end

        it "shows skipped status to the user if skip is given" do
          create_file("doc/config.rb", {}, :skip => true).should_not be_identical
          invoke!.should == "        skip  doc/config.rb\n"
        end

        it "shows forced status to the user if force is configured" do
          create_file("doc/config.rb", :force => true).should_not be_identical
          invoke!.should == "       force  doc/config.rb\n"
        end

        it "shows skipped status to the user if skip is configured" do
          create_file("doc/config.rb", :skip => true).should_not be_identical
          invoke!.should == "        skip  doc/config.rb\n"
        end

        it "shows conflict status to ther user" do
          create_file("doc/config.rb").should_not be_identical
          $stdin.should_receive(:gets).and_return('s')
          file = File.join(destination_root, 'doc/config.rb')

          content = invoke!
          content.should =~ /conflict  doc\/config\.rb/
          content.should =~ /Overwrite #{file}\? \(enter "h" for help\) \[Ynaqdh\]/
          content.should =~ /skip  doc\/config\.rb/
        end

        it "creates the file if the file collision menu returns true" do
          create_file("doc/config.rb")
          $stdin.should_receive(:gets).and_return('y')
          invoke!.should =~ /force  doc\/config\.rb/
        end

        it "skips the file if the file collision menu returns false" do
          create_file("doc/config.rb")
          $stdin.should_receive(:gets).and_return('n')
          invoke!.should =~ /skip  doc\/config\.rb/
        end

        it "executes the block given to show file content" do
          create_file("doc/config.rb")
          $stdin.should_receive(:gets).and_return('d')
          $stdin.should_receive(:gets).and_return('n')
          @base.shell.should_receive(:system).with(/diff -u/)
          invoke!
        end
      end
    end
  end

  describe "#revoke!" do
    it "removes the destination file" do
      create_file("doc/config.rb")
      invoke!
      revoke!
      File.exists?(@action.destination).should be_false
    end

    it "does not raise an error if the file does not exist" do
      create_file("doc/config.rb")
      revoke!
      File.exists?(@action.destination).should be_false
    end
  end

  describe "#exists?" do
    it "returns true if the destination file exists" do
      create_file("doc/config.rb")
      @action.exists?.should be_false
      invoke!
      @action.exists?.should be_true
    end
  end

  describe "#identical?" do
    it "returns true if the destination file and is identical" do
      create_file("doc/config.rb")
      @action.identical?.should be_false
      invoke!
      @action.identical?.should be_true
    end
  end
end
