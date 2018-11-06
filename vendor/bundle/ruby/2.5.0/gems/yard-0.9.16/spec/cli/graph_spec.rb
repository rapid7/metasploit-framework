# frozen_string_literal: true

RSpec.describe YARD::CLI::Graph do
  it "serializes output" do
    allow(Registry).to receive(:load).at_least(1).times
    allow(subject).to receive(:yardopts) { [] }
    expect(subject.options.serializer).to receive(:serialize).once
    subject.run
  end

  it "reads yardoc file from .yardopts" do
    allow(Registry).to receive(:load).at_least(1).times
    allow(subject).to receive(:yardopts) { %w(--db /path/to/db) }
    expect(subject.options.serializer).to receive(:serialize).once
    subject.run
    expect(Registry.yardoc_file).to eq '/path/to/db'
  end
end
