require "spec_helper"

describe "The File System State Monitor" do
  describe "paths" do
    it "should accept a valid filesystem directory" do
      lambda { FSSM::Path.new("#{@watch_root}") }.should_not raise_error
    end

    it "should not accept an invalid filesystem directory" do
      lambda { FSSM::Path.new('/does/not/exist/kthxbye') }.should raise_error
    end

    it "should default the path to the current directory" do
      path = FSSM::Path.new
      here = Pathname.new('.').realpath

      "#{here}".should == "#{path}"
    end

    it "should accept an optional glob array parameter" do
      path = FSSM::Path.new('.', ['**/*.yml'])
      path.glob.should == ['**/*.yml']
    end

    it "should accept an optional glob string parameter" do
      path = FSSM::Path.new('.', '**/*.yml')
      path.glob.should == ['**/*.yml']
    end

    it "should accept an optional option parameter" do
      lambda { FSSM::Path.new('.', '**/*.yml', :foo => :bar) }.should_not raise_error
    end

    it "should default the glob to ['**/*']" do
      path = FSSM::Path.new
      path.glob.should == ['**/*']
    end

    it "should accept a callback for update events" do
      path     = FSSM::Path.new
      callback = lambda { |base, relative| return true }
      path.update(&callback)
      (path.update).should == callback
    end

    it "should accept a callback for delete events" do
      path     = FSSM::Path.new
      callback = lambda { |base, relative| return true }
      path.delete(&callback)
      (path.delete).should == callback
    end

    it "should accept a callback for create events" do
      path     = FSSM::Path.new
      callback = lambda { |base, relative| return true }
      path.create(&callback)
      (path.create).should == callback
    end

    it "should accept a configuration block" do
      path = FSSM::Path.new "#{@watch_root}" do
        glob '**/*.yml'
        update { |base, relative| 'success' }
        delete { |base, relative| 'success' }
        create { |base, relative| 'success' }
      end

      "#{path}".should == "#{@watch_root}"
      path.glob.should == ['**/*.yml']
      path.update.should be_a_kind_of(Proc)
      path.delete.should be_a_kind_of(Proc)
      path.create.should be_a_kind_of(Proc)
      path.update.call('', '').should == 'success'
      path.delete.call('', '').should == 'success'
      path.create.call('', '').should == 'success'
    end

    it "should pass file type to callbacks as the third argument if :directories option is used" do
      path = FSSM::Path.new "#{@watch_root}", nil, :directories => true do
        glob '**/*.yml'
        update { |base, relative, type| [base, relative, type] }
        delete { |base, relative, type| [base, relative, type] }
        create { |base, relative, type| [base, relative, type] }
      end

      "#{path}".should == "#{@watch_root}"
      path.glob.should == ['**/*.yml']
      path.update.should be_a_kind_of(Proc)
      path.delete.should be_a_kind_of(Proc)
      path.create.should be_a_kind_of(Proc)
      path.update.call('b', 'r', 't').should == ['b', 'r', 't']
      path.delete.call('b', 'r', 't').should == ['b', 'r', 't']
      path.create.call('b', 'r', 't').should == ['b', 'r', 't']
    end
  end
end
