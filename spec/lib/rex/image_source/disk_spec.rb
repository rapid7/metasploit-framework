# -*- coding:binary -*-
require 'spec_helper'

require 'rex/image_source/disk'

describe Rex::ImageSource::Disk do

  let(:path) do
    File.join(Msf::Config.data_directory, "templates", "template_x86_windows_old.exe")
  end

  let(:file) do
    File.new(path)
  end

  describe "#initialize" do
    subject(:disk_class) do
      described_class.allocate
    end

  end

  describe "#read" do
    context "offset minor than 0" do
      let(:offset) { -1 }
      let(:len) { 20 }
    end

  end

  describe "#index" do

  end

  describe "#subsource" do

  end

  describe "#close" do

  end

end
