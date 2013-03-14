require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')
require 'thor/actions'

describe Thor::Actions::InjectIntoFile do
  before do
    ::FileUtils.rm_rf(destination_root)
    ::FileUtils.cp_r(source_root, destination_root)
  end

  def invoker(options={})
    @invoker ||= MyCounter.new([1,2], options, { :destination_root => destination_root })
  end

  def revoker
    @revoker ||= MyCounter.new([1,2], {}, { :destination_root => destination_root, :behavior => :revoke })
  end

  def invoke!(*args, &block)
    capture(:stdout){ invoker.insert_into_file(*args, &block) }
  end

  def revoke!(*args, &block)
    capture(:stdout){ revoker.insert_into_file(*args, &block) }
  end

  def file
    File.join(destination_root, "doc/README")
  end

  describe "#invoke!" do
    it "changes the file adding content after the flag" do
      invoke! "doc/README", "\nmore content", :after => "__start__"
      File.read(file).should == "__start__\nmore content\nREADME\n__end__\n"
    end

    it "changes the file adding content before the flag" do
      invoke! "doc/README", "more content\n", :before => "__end__"
      File.read(file).should == "__start__\nREADME\nmore content\n__end__\n"
    end

    it "accepts data as a block" do
      invoke! "doc/README", :before => "__end__" do
        "more content\n"
      end

      File.read(file).should == "__start__\nREADME\nmore content\n__end__\n"
    end

    it "logs status" do
      invoke!("doc/README", "\nmore content", :after => "__start__").should == "      insert  doc/README\n"
    end

    it "does not change the file if pretending" do
      invoker :pretend => true
      invoke! "doc/README", "\nmore content", :after => "__start__"
      File.read(file).should == "__start__\nREADME\n__end__\n"
    end

    it "does not change the file if already include content" do
      invoke! "doc/README", :before => "__end__" do
        "more content\n"
      end

      File.read(file).should == "__start__\nREADME\nmore content\n__end__\n"

      invoke! "doc/README", :before => "__end__" do
        "more content\n"
      end

      File.read(file).should == "__start__\nREADME\nmore content\n__end__\n"
    end

    it "does change the file if already include content and :force == true" do
      invoke! "doc/README", :before => "__end__" do
        "more content\n"
      end

      File.read(file).should == "__start__\nREADME\nmore content\n__end__\n"

      invoke! "doc/README", :before => "__end__", :force => true do
        "more content\n"
      end

      File.read(file).should == "__start__\nREADME\nmore content\nmore content\n__end__\n"
    end

  end

  describe "#revoke!" do
    it "substracts the destination file after injection" do
      invoke! "doc/README", "\nmore content", :after => "__start__"
      revoke! "doc/README", "\nmore content", :after => "__start__"
      File.read(file).should == "__start__\nREADME\n__end__\n"
    end

    it "substracts the destination file before injection" do
      invoke! "doc/README", "more content\n", :before => "__start__"
      revoke! "doc/README", "more content\n", :before => "__start__"
      File.read(file).should == "__start__\nREADME\n__end__\n"
    end

    it "substracts even with double after injection" do
      invoke! "doc/README", "\nmore content", :after => "__start__"
      invoke! "doc/README", "\nanother stuff", :after => "__start__"
      revoke! "doc/README", "\nmore content", :after => "__start__"
      File.read(file).should == "__start__\nanother stuff\nREADME\n__end__\n"
    end

    it "substracts even with double before injection" do
      invoke! "doc/README", "more content\n", :before => "__start__"
      invoke! "doc/README", "another stuff\n", :before => "__start__"
      revoke! "doc/README", "more content\n", :before => "__start__"
      File.read(file).should == "another stuff\n__start__\nREADME\n__end__\n"
    end

    it "substracts when prepending" do
      invoke! "doc/README", "more content\n", :after => /\A/
      invoke! "doc/README", "another stuff\n", :after => /\A/
      revoke! "doc/README", "more content\n", :after => /\A/
      File.read(file).should == "another stuff\n__start__\nREADME\n__end__\n"
    end

    it "substracts when appending" do
      invoke! "doc/README", "more content\n", :before => /\z/
      invoke! "doc/README", "another stuff\n", :before => /\z/
      revoke! "doc/README", "more content\n", :before => /\z/
      File.read(file).should == "__start__\nREADME\n__end__\nanother stuff\n"
    end

    it "shows progress information to the user" do
      invoke!("doc/README", "\nmore content", :after => "__start__")
      revoke!("doc/README", "\nmore content", :after => "__start__").should == "    subtract  doc/README\n"
    end
  end
end
