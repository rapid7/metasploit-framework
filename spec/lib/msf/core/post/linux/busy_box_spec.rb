# -*- coding: binary -*-
require 'spec_helper'

require 'msf/core/post/linux/busybox'

describe Msf::Post::Linux::Busybox do
  subject do
    mod = Module.new
    mod.extend described_class
    mod
  end

  describe '#file_exists' do
    it "should test for file existence" do
      result = subject.file_exists("/etc/passwd")
      result.should be true
    end
  end

  describe '#get_writable_directory' do
    it "should find a writable directory" do
      result = subject.get_writable_directory()
      result.should be true
    end
  end

  describe '#is_writable_and_write' do
    it "should write and append data to a file in a writable directory" do
      result = false
      writable_directory = get_writable_directory()
      if nil != writable_directory
        writable_file = writable_directory + "tmp"
        if is_writable_and_write(writable_file, "test write ", false) and "test write " == read_file(writable_file) and
           is_writable_and_write(writable_file, "test append", true)  and "test write test append" == read_file(writable_file)
          result = true
        end
        cmd_exec("rm -f #{writable_file}")
      end
      result.should be true
    end
  end

end
