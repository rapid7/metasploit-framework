# -*- coding:binary -*-
require 'spec_helper'

require 'msf/core'

describe FastLib do
  let(:archived_paths) do
    [
        File.join('auxiliary', 'scanner', 'portscan', 'xmas.rb'),
        File.join('exploits', 'windows', 'smb', 'ms08_067_netapi.rb')
    ]
  end

  let(:base_path) do
    File.join(Msf::Config.install_root, 'modules')
  end

  let(:extension) do
    '.fastlib'
  end

  let(:flag_compress) do
    0x01
  end

  let(:flag_encrypt) do
    0x02
  end

  let(:unarchived_paths) do
    archived_paths.collect { |archived_path|
      File.join(base_path, archived_path)
    }
  end

  context 'CONSTANTS' do
    context 'flags' do
      it 'should have compression' do
        described_class::FLAG_COMPRESS.should == flag_compress
      end

      it 'should have encryption' do
        described_class::FLAG_ENCRYPT.should == flag_encrypt
      end
    end
  end

  context 'class methods' do
    context 'dump' do
      let(:flag_string) do
        flags.to_s(16)
      end

      before(:each) do
        FastLib.cache.clear
      end

      around(:each) do |example|
        Dir.mktmpdir do |directory|
          @destination_path = File.join(directory, "rspec#{extension}")

          example.run
        end
      end

      context 'without compression and without encryption' do
        let(:flags) do
          0x0
        end

        it 'should create an archive' do
          File.exist?(@destination_path).should be_false

          described_class.dump(@destination_path, flag_string, base_path, *unarchived_paths)

          File.exist?(@destination_path).should be_true
        end

        context 'cache' do
          it 'should populate' do
            FastLib.cache[@destination_path].should be_nil

            described_class.dump(@destination_path, flag_string, base_path, *unarchived_paths)

            FastLib.cache[@destination_path].should be_a Hash
          end

          it 'should include flags' do
            described_class.dump(@destination_path, flag_string, base_path, *unarchived_paths)

            FastLib.cache[@destination_path][:fastlib_flags].should == flags
          end

          pending "Fix https://www.pivotaltracker.com/story/show/38730815" do
            it 'should include header' do
              described_class.dump(@destination_path, flag_string, base_path, *unarchived_paths)
              header = FastLib.cache[@destination_path][:fastlib_header]
              modification_time = File.mtime(@destination_path).utc.to_i

              header.should be_a Array
              # @todo figure out why 12 before header length
              header[0].should == 12
              # @todo figure out why header length is 0
              header[1].should == 0
              header[2].should == modification_time
            end

            it 'should include archived paths' do
              described_class.dump(@destination_path, flag_string, base_path, *unarchived_paths)
              cache = FastLib.cache[@destination_path]

              archived_path = File.join('exploits', 'windows', 'smb', 'ms08_067_netapi.rb')
              unarchived_path = File.join(base_path, archived_path)

              # make sure that the unarchived module exists and hasn't be deleted or renamed before expecting it to be
              # in the archive.
              File.exist?(unarchived_path).should be_true
              cache[archived_path].should_not be_nil
            end
          end
        end
      end

      context 'with compression and without encryption' do
        let(:flags) do
          flag_compress
        end

        it 'should create an archive' do
          File.exist?(@destination_path).should be_false

          described_class.dump(@destination_path, flag_string, base_path, *unarchived_paths)

          File.exist?(@destination_path).should be_true
        end

        it 'should be smaller than the uncompressed archive' do
          uncompressed_path = "#{@destination_path}.uncompressed"
          compressed_path = "#{@destination_path}.compressed"

          File.exist?(uncompressed_path).should be_false
          File.exist?(compressed_path).should be_false

          described_class.dump(uncompressed_path, '', base_path, *unarchived_paths)
          described_class.dump(compressed_path, flag_string, base_path, *unarchived_paths)

          File.exist?(uncompressed_path).should be_true
          File.exist?(compressed_path).should be_true

          File.size(compressed_path).should < File.size(uncompressed_path)
        end
      end

      context 'without compression and with encryption' do
        let(:flags) do
          flag_encrypt
        end

        it 'should create an archive' do
          File.exist?(@destination_path).should be_false

          described_class.dump(@destination_path, flag_string, base_path, *unarchived_paths)

          File.exist?(@destination_path).should be_true
        end
      end

      context 'with compression and with encryption' do
        let(:flags) do
          flag_compress | flag_encrypt
        end

        it 'should create an archive' do
          File.exist?(@destination_path).should be_false

          described_class.dump(@destination_path, flag_string, base_path, *unarchived_paths)

          File.exist?(@destination_path).should be_true
        end
      end
    end

    context 'list' do
      around(:each) do |example|
        Dir.mktmpdir do |directory|
          @destination_path = File.join(directory, "rspec#{extension}")

          FastLib.dump(@destination_path, FastLib::FLAG_COMPRESS.to_s, base_path, *unarchived_paths)

          example.run
        end
      end

      # ensure modules expected to be listed actually exist
      it 'should use existent unarchived modules' do
        unarchived_paths.each do |unarchived_path|
          File.exist?(unarchived_path).should be_true
        end
      end

      context 'with cached dump', :pending => "Fix https://www.pivotaltracker.com/story/show/38730815" do
        it 'should have dump cached' do
          FastLib.cache[@destination_path].should_not be_nil
        end

        it 'should list archived paths' do
          paths = FastLib.list(@destination_path)

          paths.length.should == archived_paths.length
          paths.should == archived_paths
        end
      end

      context 'without cached dump' do
        before(:each) do
          FastLib.cache.clear
        end

        it 'should not have dump cache' do
          FastLib.cache[@destination_path].should be_nil
        end

        it 'should list archived paths' do
          paths = FastLib.list(@destination_path)

          paths.length.should == archived_paths.length
          paths.should == archived_paths
        end
      end
    end
  end
end
