# frozen_string_literal: true

RSpec.describe YARD::Rake::YardocTask do
  before do
    @yardoc = YARD::CLI::Yardoc.new
    @yardoc.statistics = false
    @yardoc.use_document_file = false
    @yardoc.use_yardopts_file = false
    @yardoc.generate = false
    allow(Templates::Engine).to receive(:render)
    allow(Templates::Engine).to receive(:generate)
    allow(YARD).to receive(:parse)
    allow(Registry).to receive(:load)
    allow(Registry).to receive(:save)
    allow(YARD::CLI::Yardoc).to receive(:new).and_return(@yardoc)
    ::Rake.application.clear
  end

  def run
    ::Rake.application.tasks[0].invoke
  end

  describe "#initialize" do
    it "allows separate rake task name to be set" do
      YARD::Rake::YardocTask.new(:notyardoc)
      expect(::Rake.application.tasks[0].name).to eq "notyardoc"
    end
  end

  describe "#files" do
    it "allows files to be set" do
      YARD::Rake::YardocTask.new do |t|
        t.files = ['a', 'b', 'c']
      end
      run
      expect(@yardoc.files).to eq %w(a b c)
    end
  end

  describe "#options" do
    it "allows extra options to be set" do
      YARD::Rake::YardocTask.new do |t|
        t.options = ['--private', '--protected']
      end
      run
      expect(@yardoc.visibilities).to eq [:public, :private, :protected]
    end

    it "allows --api and --no-api" do
      YARD::Rake::YardocTask.new do |t|
        t.options = %w(--api public --no-api)
      end
      run
      expect(@yardoc.options.verifier.expressions).to include('["public"].include?(@api.text) || !@api')
    end
  end

  describe "#stats_options" do
    before do
      @yard_stats = Object.new
      allow(@yard_stats).to receive(:run)
      allow(YARD::CLI::Stats).to receive(:new).and_return(@yard_stats)
    end

    it "invokes stats" do
      expect(@yard_stats).to receive(:run).with('--list-undoc', '--use-cache')
      @yardoc.statistics = true
      YARD::Rake::YardocTask.new do |t|
        t.stats_options = %w(--list-undoc)
      end
      run
      expect(@yardoc.statistics).to be false
    end
  end

  describe "#before" do
    it "allows before callback" do
      proc = lambda {}
      expect(proc).to receive(:call)
      expect(@yardoc).to receive(:run)
      YARD::Rake::YardocTask.new {|t| t.before = proc }
      run
    end
  end

  describe "#after" do
    it "allows after callback" do
      proc = lambda {}
      expect(proc).to receive(:call)
      expect(@yardoc).to receive(:run)
      YARD::Rake::YardocTask.new {|t| t.after = proc }
      run
    end
  end

  describe "#verifier" do
    it "allows a verifier proc to be set" do
      verifier = Verifier.new
      expect(@yardoc).to receive(:run) do
        expect(@yardoc.options[:verifier]).to eq verifier
      end
      YARD::Rake::YardocTask.new {|t| t.verifier = verifier }
      run
    end

    it "overrides --query options" do
      verifier = Verifier.new
      expect(@yardoc).to receive(:run) do
        expect(@yardoc.options[:verifier]).to eq verifier
      end
      YARD::Rake::YardocTask.new do |t|
        t.options += ['--query', '@return']
        t.verifier = verifier
      end
      run
    end
  end
end
