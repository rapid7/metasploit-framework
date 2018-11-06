# frozen_string_literal: true
require 'yaml'

RSpec.describe YARD::CLI::Config do
  before do
    @config = YARD::CLI::Config.new
    YARD::Config.options = YARD::Config::DEFAULT_CONFIG_OPTIONS.dup
    allow(YARD::Config).to receive(:save)
  end

  def run(*args)
    @config.run(*args)
  end

  describe "Listing configuration" do
    it "accepts --list" do
      opts = YARD::Config.options
      expect(YAML).to receive(:dump).twice.and_return("--- foo\nbar\nbaz")
      expect(log).to receive(:puts).twice.with("bar\nbaz")
      run
      run('--list')
      expect(YARD::Config.options).to eq opts
    end
  end

  describe "Viewing an item" do
    it "views item if no value is given" do
      YARD::Config.options[:foo] = 'bar'
      expect(log).to receive(:puts).with('"bar"')
      run 'foo'
      expect(YARD::Config.options[:foo]).to eq 'bar'
    end
  end

  describe "Modifying an item" do
    it "accepts --reset to set value" do
      YARD::Config.options[:load_plugins] = 'foo'
      run('--reset', 'load_plugins')
      expect(YARD::Config.options[:load_plugins]).to be false
    end

    it "accepts --as-list to force single item as list" do
      run('--as-list', 'foo', 'bar')
      expect(YARD::Config.options[:foo]).to eq ['bar']
    end

    it "accepts --append to append values to existing key" do
      YARD::Config.options[:foo] = ['bar']
      run('--append', 'foo', 'baz', 'quux')
      expect(YARD::Config.options[:foo]).to eq ['bar', 'baz', 'quux']
      run('-a', 'foo', 'last')
      expect(YARD::Config.options[:foo]).to eq ['bar', 'baz', 'quux', 'last']
    end

    it "turns key into list if --append is used on single item" do
      YARD::Config.options[:foo] = 'bar'
      run('-a', 'foo', 'baz')
      expect(YARD::Config.options[:foo]).to eq ['bar', 'baz']
    end

    it "modifies item if value is given" do
      run('foo', 'xxx')
      expect(YARD::Config.options[:foo]).to eq 'xxx'
    end

    it "turns list of values into array of values" do
      run('foo', 'a', 'b', '1', 'true', 'false')
      expect(YARD::Config.options[:foo]).to eq ['a', 'b', 1, true, false]
    end

    it "turns number into numeric Ruby type" do
      run('foo', '1')
      expect(YARD::Config.options[:foo]).to eq 1
    end

    it "turns true into TrueClass" do
      run('foo', 'true')
      expect(YARD::Config.options[:foo]).to be true
    end

    it "turns false into FalseClass" do
      run('foo', 'false')
      expect(YARD::Config.options[:foo]).to be false
    end

    it "saves on modification" do
      expect(YARD::Config).to receive(:save)
      run('foo', 'true')
    end
  end

  describe "RubyGems hooks" do
    require 'rubygems'

    class FakeGemConfig < Hash
      attr_accessor :written
      def write; @written = true end
      def path; nil end
    end

    before do
      allow(Gem).to receive(:configuration).and_return(FakeGemConfig.new)
    end

    it "accepts --gem-install-yri" do
      @config.send(:optparse, '--gem-install-yri')
      expect(@config.gem_install_cmd).to eq 'yri'
    end

    it "accepts --gem-install-yard" do
      @config.send(:optparse, '--gem-install-yard')
      expect(@config.gem_install_cmd).to eq 'yard'
    end

    it "does not change back to yri if yard was specified" do
      @config.send(:optparse, '--gem-install-yard', '--gem-install-yri')
      expect(@config.gem_install_cmd).to eq 'yard'
    end

    it "ignores actual config options" do
      run('--gem-install-yri', 'foo', 'true')
      expect(YARD::Config).not_to receive(:save)
    end

    it "updates configuration as :gem if no configuration exists" do
      run('--gem-install-yri')
      expect(Gem.configuration[:gem]).to eq "--document=yri"
      expect(Gem.configuration.written).to eq true
    end

    [:install, "install", :gem, "gem"].each do |type|
      it "finds existing config in #{type.inspect} and updates that line without changing anything else" do
        Gem.configuration[type] = "--opts x"
        run('--gem-install-yri')
        expect(Gem.configuration[type]).to eq "--opts x --document=yri"
        ([:install, "install", :gem, "gem"] - [type]).each do |other|
          expect(Gem.configuration[other]).to eq nil
        end
      end
    end

    it "scrubs --document values from existing config" do
      Gem.configuration["gem"] = "--document=yri,ri --no-document --opts x"
      run('--gem-install-yri')
      expect(Gem.configuration["gem"]).to eq "--opts x --document=yri"
    end
  end
end
