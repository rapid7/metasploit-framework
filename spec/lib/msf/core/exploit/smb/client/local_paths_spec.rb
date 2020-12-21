# -*- coding:binary -*-
require 'spec_helper'

require 'msf/core'
require 'msf/core/data_store'

RSpec.describe Msf::Exploit::Remote::SMB::Client::LocalPaths do
  subject do
    mod = ::Msf::Module.new
    mod.extend described_class
    mod
  end

  before(:context) do
    prefix = "local_#{Rex::Text.rand_text_alpha(10)}"
    # create a single random file to be used for LPATH
    @lpath = prefix
    # create file containing several random file names to be used for FILE_LPATHS
    @indices = Array(0..(1 + rand(5))).map(&:to_s)
    @file_lpaths = Tempfile.new(prefix)

    File.open(@file_lpaths, 'wb') do |f|
      @indices.map do |i|
        f.puts(i)
      end
    end
  end

  describe '#setup' do
    context 'when PATH and FILE_LPATHS are not set correctly' do
      it 'raises if both are set' do
        subject.datastore['LPATH'] = @lpath
        subject.datastore['FILE_LPATHS'] = @file_lpaths
        expect { subject.setup }.to raise_error(RuntimeError, /bad\-config/)
      end

      it 'should raise if neither are set' do
        expect { subject.setup }.to raise_error(RuntimeError, /bad\-config/)
      end
    end

  end

  describe '#local_paths' do
    context 'when LPATH and FILE_LPATHS are set correctly' do
      it 'returns one remote file if LPATH is set' do
        subject.datastore['LPATH'] = @lpath
        expect(subject.local_paths).to eql([@lpath])
      end

      it 'returns all files if FILE_LPATHS is set' do
        subject.datastore['FILE_LPATHS'] = @file_lpaths
        expect(subject.local_paths).to eql(@indices)
      end
    end
  end

  after(:context) do
    @file_lpaths.unlink
  end
end
