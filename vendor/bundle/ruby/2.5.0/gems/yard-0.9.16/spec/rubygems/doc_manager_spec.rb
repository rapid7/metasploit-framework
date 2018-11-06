# frozen_string_literal: true
require File.join(YARD::ROOT, 'rubygems_plugin')
require 'fileutils'

RSpec.describe Gem::DocManager do
  before do
    # Ensure filesystem integrity
    allow(FileUtils).to receive(:mkdir_p)
    allow(FileUtils).to receive(:rm_rf)
    allow(Dir).to receive(:chdir)

    allow(YARD::CLI::Yardoc).to receive(:run)

    @spec_file = File.join(YARD::ROOT, '..', 'yard.gemspec')
    @spec = Gem::SourceIndex.load_specification(@spec_file)
    @spec.has_yardoc = false # no yardoc docs for now
    @yardopts = File.join(@spec.full_gem_path, '.yardopts')
    @doc = Gem::DocManager.new(@spec)
    allow(@doc).to receive(:install_ri_yard_orig)
    allow(@doc).to receive(:install_rdoc_yard_orig)
  end

  def runs; expect(YARD::CLI::Yardoc).to receive(:run) end

  describe ".load_yardoc" do
    it "properly loads YARD" do
      expect(Gem::DocManager).to receive(:require) do |path|
        expect(File.expand_path(path)).to eq YARD::ROOT + '/yard'
      end
      Gem::DocManager.load_yardoc
    end
  end

  describe "#install_ri_yard" do
    def install
      msg = "Building YARD (yri) index for #{@spec.full_name}..."
      expect(@doc).to receive(:say).with(msg)
      @doc.install_ri_yard
    end

    it "passes --quiet to all documentation" do
      runs.with('-c', '-n', '--quiet', 'lib')
      install
    end

    it "passes extra_rdoc_files to documentation" do
      @spec.extra_rdoc_files = %w(README LICENSE)
      runs.with('-c', '-n', '--quiet', 'lib', '-', 'README', 'LICENSE')
      install
    end

    it "adds --backtrace if Gem.configuration.backtrace" do
      Gem.configuration.backtrace = true
      runs.with('-c', '-n', '--quiet', '--backtrace', 'lib')
      install
      Gem.configuration.backtrace = false
    end

    it "adds require_paths if there is no .yardopts" do
      expect(File).to receive(:file?).with(@yardopts).and_return(true)
      runs.with('-c', '-n', '--quiet')
      install
    end

    it "adds extra_rdoc_files if there is no .yardopts" do
      @spec.extra_rdoc_files = %w(README LICENSE)
      expect(File).to receive(:file?).with(@yardopts).and_return(true)
      runs.with('-c', '-n', '--quiet')
      install
    end

    it "switches to directory before running command" do
      old = Dir.pwd
      expect(Dir).to receive(:chdir).with(@spec.full_gem_path)
      expect(Dir).to receive(:chdir).with(old)
      install
    end

    it "ensures that directory is switched back at end of command in failure" do
      old = Dir.pwd
      expect(Dir).to receive(:chdir).with(@spec.full_gem_path)
      expect(Dir).to receive(:chdir).with(old)
      expect(@doc.ui.errs).to receive(:puts).with(/ERROR:\s*While generating documentation/)
      expect(@doc.ui.errs).to receive(:puts).with(/MESSAGE:\s*foo/)
      expect(@doc.ui.errs).to receive(:puts).with(/YARDOC args:\s*-c -n --quiet lib/)
      expect(@doc.ui.errs).to receive(:puts).with("(continuing with the rest of the installation)")
      expect(YARD::CLI::Yardoc).to receive(:run).and_raise(RuntimeError.new("foo"))
      install
    end

    it "handles permission errors" do
      expect(YARD::CLI::Yardoc).to receive(:run).and_raise(Errno::EACCES.new("- dir"))
      expect { install }.to raise_error(Gem::FilePermissionError)
    end
  end

  describe "#install_rdoc_yard" do
    def install
      msg = "Installing YARD documentation for #{@spec.full_name}..."
      expect(@doc).to receive(:say).with(msg)
      @doc.install_rdoc_yard
    end

    it "adds -o outdir when generating docs" do
      expect(File).to receive(:file?).with(@yardopts).and_return(true)
      @spec.has_yardoc = true
      doc_dir = File.join(@doc.instance_variable_get("@doc_dir"), 'rdoc')
      runs.with('-o', doc_dir, '--quiet')
      install
    end
  end
end if Gem::VERSION < '2.0.0'
