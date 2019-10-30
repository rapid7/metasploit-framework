# -*- coding: binary -*-
require 'spec_helper'

require 'msf/core/post/linux/busy_box'

RSpec.describe Msf::Post::Linux::BusyBox do
  subject do
    mod = ::Msf::Module.new
    mod.extend described_class
    mod
  end

  describe "#busy_box_file_exist?" do
    describe "when file exists" do
      before :example do
        allow(subject).to receive(:read_file) do
          'test data'
        end
      end

      it "returns true" do
        expect(subject.busy_box_file_exist?('/etc/passwd')).to be_truthy
      end
    end

    describe "when file doesn't exist" do
      before :example do
        allow(subject).to receive(:read_file) do
          ''
        end
      end

      it "returns false" do
        expect(subject.busy_box_file_exist?('/etc/nonexistent')).to be_falsey
      end
    end
  end

  describe "#busy_box_is_writable_dir?" do
    before :example do
      allow(subject).to receive(:cmd_exec) do
        ''
      end
    end

    describe "when dir is writable" do
      before :example do
        allow(subject).to receive(:read_file) do
          "#{'A' * 16}XXX#{'A' * 16}"
        end

        allow(Rex::Text).to receive(:rand_text_alpha) do
          'A' * 16
        end
      end

      it "returns true" do
        expect(subject.busy_box_is_writable_dir?('/tmp/')).to be_truthy
      end
    end

    describe "when dir isn't writable" do
      before :example do
        allow(subject).to receive(:read_file) do
          ''
        end
      end

      it "returns false" do
        expect(subject.busy_box_is_writable_dir?('/etc/')).to be_falsey
      end
    end
  end


  describe "#busy_box_writable_dir" do
    before :example do
      allow(subject).to receive(:cmd_exec) do
        ''
      end
    end

    describe "when a writable directory doesn't exist" do
      before :example do
        allow(subject).to receive(:read_file) do
          ''
        end
      end

      it "returns nil" do
        expect(subject.busy_box_writable_dir).to be_nil
      end
    end

    describe "when a writable directory exists" do
      before :example do
        allow(subject).to receive(:read_file) do
          "#{'A' * 16}XXX#{'A' * 16}"
        end

        allow(Rex::Text).to receive(:rand_text_alpha) do
          'A' * 16
        end
      end

      it "returns the writable dir path" do
        expect(subject.busy_box_writable_dir).to eq('/etc/')
      end
    end
  end


  describe "#busy_box_write_file" do
    before :example do
      allow(subject).to receive(:cmd_exec) do
        ''
      end
    end

    describe "when the file isn't writable" do
      before :example do
        allow(subject).to receive(:read_file) do
          ''
        end
      end

      it "returns false" do
        expect(subject.busy_box_write_file('/etc/passwd', 'test')).to be_falsey
      end
    end

    describe "when the file is writable" do
      before :example do
        allow(subject).to receive(:read_file) do
          "#{'A' * 16}XXX#{'A' * 16}"
        end

        allow(Rex::Text).to receive(:rand_text_alpha) do
          'A' * 16
        end
      end

      it "returns true" do
        expect(subject.busy_box_write_file('/tmp/test', 'test')).to be_truthy
      end
    end

    describe "when prepend is true" do
      describe "when there is a writable dir" do
        describe "when the target file is writable" do
          before :example do
            allow(subject).to receive(:busy_box_writable_dir) do
              '/tmp/'
            end

            allow(subject).to receive(:read_file) do
              "#{'A' * 16}XXX#{'A' * 16}"
            end

            allow(Rex::Text).to receive(:rand_text_alpha) do
              'A' * 16
            end
          end

          it "returns true" do
            expect(subject.busy_box_write_file('/tmp/test', 'test', true)).to be_truthy
          end
        end
      end

      describe "when there isn't a writable dir" do
        before :example do
          allow(subject).to receive(:busy_box_writable_dir) do
            nil
          end
        end
        
        it "returns false" do
          expect(subject.busy_box_write_file('/tmp/test', 'test', true)).to be_falsey
        end
      end
    end
  end

end
