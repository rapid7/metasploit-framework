require 'spec_helper'

require 'count_down_latch'
require 'fileutils'
require 'tempfile'

module FSSM::MonitorSpecHelpers
  def create_tmp_dir
    @tmp_dir = FSSM::Pathname.for(Dir.mktmpdir).realpath.to_s
    FileUtils.cp_r File.join(File.dirname(__FILE__), 'root'), @tmp_dir
    # Because git does not track empty directories, create one ourselves.
    FileUtils.mkdir_p @tmp_dir + '/root/yawn'
    @tmp_dir
  end

  def remove_tmp_dir
    FileUtils.remove_entry @tmp_dir
  end

  def create_handler(type, latch)
    lambda do |*args|
      @handler_results[type] << args
      latch.count_down
    end
  end

  def run_monitor(num_events_to_expect=0, options={})
    event_latch      = CountDownLatch.new(num_events_to_expect)
    @handler_results = Hash.new { |hash, key| hash[key] = [] }
    thread           = Thread.new do
      monitor = FSSM::Monitor.new(options)
      monitor.path(@tmp_dir) do |p|
        p.create(&create_handler(:create, event_latch))
        p.update(&create_handler(:update, event_latch))
        p.delete(&create_handler(:delete, event_latch))
      end
      monitor.run
    end
    sleep 1 # give time for monitor to start up
    yield if block_given?
    event_latch.wait
    thread.kill
  end
end

describe "The File System State Monitor" do
  describe "monitor" do
    include FSSM::MonitorSpecHelpers

    before do
      create_tmp_dir
    end

    after do
      remove_tmp_dir
    end

    describe "with default options" do
      it "should call create callback upon file creation" do
        run_monitor(1) do
          file = @tmp_dir + "/newfile.rb"
          File.exists?(file).should be_false
          FileUtils.touch file
        end
        @handler_results[:create].should == [[@tmp_dir, 'newfile.rb']]
      end

      it "should call update callback upon file modification" do
        run_monitor(1) do
          FileUtils.touch @tmp_dir + '/root/file.rb'
        end
        @handler_results[:update].should == [[@tmp_dir, 'root/file.rb']]
      end

      it "should call delete callback upon file deletion" do
        run_monitor(1) do
          FileUtils.rm @tmp_dir + "/root/file.rb"
        end
        @handler_results[:delete].should == [[@tmp_dir, 'root/file.rb']]
      end

      it "should call create and delete callbacks upon file renaming in the same directory" do
        run_monitor(2) do
          FileUtils.mv @tmp_dir + "/root/file.rb", @tmp_dir + "/root/old_file.rb"
        end
        @handler_results[:create].should == [[@tmp_dir, 'root/old_file.rb']]
        @handler_results[:delete].should == [[@tmp_dir, 'root/file.rb']]
        @handler_results[:update].should == []
      end

      it "should call create and delete callbacks upon file moving to another directory" do
        run_monitor(2) do
          FileUtils.mv @tmp_dir + "/root/file.rb", @tmp_dir + "/old_file.rb"
        end
        @handler_results[:create].should == [[@tmp_dir, 'old_file.rb']]
        @handler_results[:delete].should == [[@tmp_dir, 'root/file.rb']]
        @handler_results[:update].should == []
      end

      it "should not call callbacks upon directory operations" do
        run_monitor do
          FileUtils.mkdir @tmp_dir + "/another_yawn"
          FileUtils.rmdir @tmp_dir + "/root/yawn"
        end
        @handler_results[:create].should == []
        @handler_results[:delete].should == []
      end
    end

    describe "when configured to consider files and directories" do
      it "should call create callback upon directory creation" do
        run_monitor(1, :directories => true) do
          FileUtils.mkdir @tmp_dir + "/another_yawn"
        end
        @handler_results[:create].should include([@tmp_dir, 'another_yawn', :directory])
      end

      it "should call delete callback upon directory deletion" do
        run_monitor(1, :directories => true) do
          FileUtils.rmdir @tmp_dir + "/root/yawn"
        end
        @handler_results[:delete].should include([@tmp_dir, 'root/yawn', :directory])
      end

      it "should call create, update, and delete callbacks upon directory renaming in the same directory" do
        run_monitor(3, :directories => true) do
          FileUtils.mv @tmp_dir + "/root/yawn", @tmp_dir + "/root/old_yawn"
        end
        @handler_results[:create].should include([@tmp_dir, 'root/old_yawn', :directory])
        @handler_results[:delete].should include([@tmp_dir, 'root/yawn', :directory])
        @handler_results[:update].should include([@tmp_dir, 'root', :directory])
      end

      it "should call create, update, and delete callbacks upon directory moving to another directory" do
        run_monitor(3, :directories => true) do
          FileUtils.mv @tmp_dir + "/root/yawn", @tmp_dir + "/old_yawn"
        end
        @handler_results[:create].should include([@tmp_dir, 'old_yawn', :directory])
        @handler_results[:delete].should include([@tmp_dir, 'root/yawn', :directory])
        @handler_results[:update].should include([@tmp_dir, 'root', :directory])
      end

      it "should call create, update, and delete callbacks upon file renaming in the same directory" do
        run_monitor(3, :directories => true) do
          FileUtils.mv @tmp_dir + "/root/file.rb", @tmp_dir + "/root/old_file.rb"
        end
        @handler_results[:create].should include([@tmp_dir, 'root/old_file.rb', :file])
        @handler_results[:delete].should include([@tmp_dir, 'root/file.rb', :file])
        @handler_results[:update].should include([@tmp_dir, 'root', :directory])
      end

      it "should call create, update, and delete callbacks upon file moving to another directory" do
        run_monitor(3, :directories => true) do
          FileUtils.mv @tmp_dir + "/root/file.rb", @tmp_dir + "/old_file.rb"
        end
        @handler_results[:create].should include([@tmp_dir, 'old_file.rb', :file])
        @handler_results[:delete].should include([@tmp_dir, 'root/file.rb', :file])
        @handler_results[:update].should include([@tmp_dir, 'root', :directory])
      end

      it "should call delete callbacks upon directory structure deletion, in reverse order" do
        expected_delete_events = [
            ['root/yawn', :directory],
            ['root/moo/cow.txt', :file],
            ['root/moo', :directory],
            ['root/file.yml', :file],
            ['root/file.rb', :file],
            ['root/file.css', :file],
            ['root/duck/quack.txt', :file],
            ['root/duck', :directory],
            ['root', :directory]
        ]
        run_monitor(expected_delete_events.size, :directories => true) do
          FileUtils.rm_rf @tmp_dir + '/.'
        end
        @handler_results[:create].should == []
        @handler_results[:delete].should == expected_delete_events.map { |(file, type)| [@tmp_dir, file, type] }
        @handler_results[:update].should == []
      end

      it "should call create callbacks upon directory structure creation, in order" do
        expected_create_events = [
            ['new_root', :directory],
            ['new_root/duck', :directory],
            ['new_root/duck/quack.txt', :file],
            ['new_root/file.css', :file],
            ['new_root/file.rb', :file],
            ['new_root/file.yml', :file],
            ['new_root/moo', :directory],
            ['new_root/moo/cow.txt', :file],
            ['new_root/yawn', :directory]
        ]
        run_monitor(expected_create_events.size, :directories => true) do
          FileUtils.cp_r @tmp_dir + '/root/.', @tmp_dir + '/new_root'
        end
        @handler_results[:create].should == expected_create_events.map { |(file, type)| [@tmp_dir, file, type] }
        @handler_results[:delete].should == []
        @handler_results[:update].should == []
      end
    end
  end
end
