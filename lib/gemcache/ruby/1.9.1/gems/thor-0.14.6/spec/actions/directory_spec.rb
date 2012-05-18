require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')
require 'thor/actions'

describe Thor::Actions::Directory do
  before(:each) do
    ::FileUtils.rm_rf(destination_root)
    invoker.stub!(:file_name).and_return("rdoc")
  end

  def invoker
    @invoker ||= WhinyGenerator.new([1,2], {}, { :destination_root => destination_root })
  end

  def revoker
    @revoker ||= WhinyGenerator.new([1,2], {}, { :destination_root => destination_root, :behavior => :revoke })
  end

  def invoke!(*args, &block)
    capture(:stdout){ invoker.directory(*args, &block) }
  end

  def revoke!(*args, &block)
    capture(:stdout){ revoker.directory(*args, &block) }
  end

  def exists_and_identical?(source_path, destination_path)
    %w(config.rb README).each do |file|
      source      = File.join(source_root, source_path, file)
      destination = File.join(destination_root, destination_path, file)

      File.exists?(destination).should be_true
      FileUtils.identical?(source, destination).should be_true
    end
  end

  describe "#invoke!" do
    it "raises an error if the source does not exist" do
      lambda {
        invoke! "unknown"
      }.should raise_error(Thor::Error, /Could not find "unknown" in any of your source paths/)
    end

    it "should not create a directory in pretend mode" do
      invoke! "doc", "ghost", :pretend => true
      File.exists?("ghost").should be_false
    end

    it "copies the whole directory recursively to the default destination" do
      invoke! "doc"
      exists_and_identical?("doc", "doc")
    end

    it "copies the whole directory recursively to the specified destination" do
      invoke! "doc", "docs"
      exists_and_identical?("doc", "docs")
    end

    it "copies only the first level files if recursive" do
      invoke! ".", "tasks", :recursive => false

      file = File.join(destination_root, "tasks", "group.thor")
      File.exists?(file).should be_true

      file = File.join(destination_root, "tasks", "doc")
      File.exists?(file).should be_false

      file = File.join(destination_root, "tasks", "doc", "README")
      File.exists?(file).should be_false
    end

    it "copies files from the source relative to the current path" do
      invoker.inside "doc" do
        invoke! "."
      end
      exists_and_identical?("doc", "doc")
    end

    it "copies and evaluates templates" do
      invoke! "doc", "docs"
      file = File.join(destination_root, "docs", "rdoc.rb")
      File.exists?(file).should be_true
      File.read(file).should == "FOO = FOO\n"
    end

    it "copies directories" do
      invoke! "doc", "docs"
      file = File.join(destination_root, "docs", "components")
      File.exists?(file).should be_true
      File.directory?(file).should be_true
    end

    it "does not copy .empty_directory files" do
      invoke! "doc", "docs"
      file = File.join(destination_root, "docs", "components", ".empty_directory")
      File.exists?(file).should be_false
    end

    it "copies directories even if they are empty" do
      invoke! "doc/components", "docs/components"
      file = File.join(destination_root, "docs", "components")
      File.exists?(file).should be_true
    end

    it "does not copy empty directories twice" do
      content = invoke!("doc/components", "docs/components")
      content.should_not =~ /exist/
    end

    it "logs status" do
      content = invoke!("doc")
      content.should =~ /create  doc\/README/
      content.should =~ /create  doc\/config\.rb/
      content.should =~ /create  doc\/rdoc\.rb/
      content.should =~ /create  doc\/components/
    end

    it "yields a block" do
      checked = false
      invoke!("doc") do |content|
        checked ||= !!(content =~ /FOO/)
      end
      checked.should be_true
    end
  end

  describe "#revoke!" do
    it "removes the destination file" do
      invoke! "doc"
      revoke! "doc"

      File.exists?(File.join(destination_root, "doc", "README")).should be_false
      File.exists?(File.join(destination_root, "doc", "config.rb")).should be_false
      File.exists?(File.join(destination_root, "doc", "components")).should be_false
    end
  end
end
