require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')
require 'thor/actions'

describe Thor::Actions::EmptyDirectory do
  before do
    ::FileUtils.rm_rf(destination_root)
  end

  def empty_directory(destination, options={})
    @action = Thor::Actions::EmptyDirectory.new(base, destination)
  end

  def invoke!
    capture(:stdout){ @action.invoke! }
  end

  def revoke!
    capture(:stdout){ @action.revoke! }
  end

  def base
    @base ||= MyCounter.new([1,2], {}, { :destination_root => destination_root })
  end

  describe "#destination" do
    it "returns the full destination with the destination_root" do
      empty_directory('doc').destination.should == File.join(destination_root, 'doc')
    end

    it "takes relative root into account" do
      base.inside('doc') do
        empty_directory('contents').destination.should == File.join(destination_root, 'doc', 'contents')
      end
    end
  end

  describe "#relative_destination" do
    it "returns the relative destination to the original destination root" do
      base.inside('doc') do
        empty_directory('contents').relative_destination.should == 'doc/contents'
      end
    end
  end

  describe "#given_destination" do
    it "returns the destination supplied by the user" do
      base.inside('doc') do
        empty_directory('contents').given_destination.should == 'contents'
      end
    end
  end

  describe "#invoke!" do
    it "copies the file to the specified destination" do
      empty_directory("doc")
      invoke!
      File.exists?(File.join(destination_root, "doc")).should be_true
    end

    it "shows created status to the user" do
      empty_directory("doc")
      invoke!.should == "      create  doc\n"
    end

    it "does not create a directory if pretending" do
      base.inside("foo", :pretend => true) do
        empty_directory("ghost")
      end
      File.exists?(File.join(base.destination_root, "ghost")).should be_false
    end

    describe "when directory exists" do
      it "shows exist status" do
        empty_directory("doc")
        invoke!
        invoke!.should == "       exist  doc\n"
      end
    end
  end

  describe "#revoke!" do
    it "removes the destination file" do
      empty_directory("doc")
      invoke!
      revoke!
      File.exists?(@action.destination).should be_false
    end
  end

  describe "#exists?" do
    it "returns true if the destination file exists" do
      empty_directory("doc")
      @action.exists?.should be_false
      invoke!
      @action.exists?.should be_true
    end
  end

  context "protected methods" do
    describe "#convert_encoded_instructions" do
      before do
        empty_directory("test_dir")
        @action.base.stub!(:file_name).and_return("expected")
      end

      it "accepts and executes a 'legal' %\w+% encoded instruction" do
        @action.send(:convert_encoded_instructions, "%file_name%.txt").should == "expected.txt"
      end

      it "ignores an 'illegal' %\w+% encoded instruction" do
        @action.send(:convert_encoded_instructions, "%some_name%.txt").should == "%some_name%.txt"
      end

      it "ignores incorrectly encoded instruction" do
        @action.send(:convert_encoded_instructions, "%some.name%.txt").should == "%some.name%.txt"
      end

      it "raises an error if the instruction refers to a private method" do
        module PrivExt
          private
          def private_file_name
            "something_hidden"
          end
        end
        @action.base.extend(PrivExt)
        expect { @action.send(:convert_encoded_instructions, "%private_file_name%.txt") }.to raise_error Thor::PrivateMethodEncodedError
      end
    end
  end
end
