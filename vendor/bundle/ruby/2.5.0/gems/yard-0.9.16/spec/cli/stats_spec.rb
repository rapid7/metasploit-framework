# frozen_string_literal: true
require 'stringio'

RSpec.describe YARD::CLI::Stats do
  before do
    Registry.clear
    YARD.parse_string <<-eof
      class A
        CONST = 1

        def foo; end

        attr_reader :fooattr

        # Documented
        def bar; end
      end
      module B; end
    eof

    @main_stats =
      "Files:           1\n" \
      "Modules:         1 (    1 undocumented)\n" \
      "Classes:         1 (    1 undocumented)\n" \
      "Constants:       1 (    1 undocumented)\n" \
      "Attributes:      1 (    0 undocumented)\n" \
      "Methods:         2 (    1 undocumented)\n" \
      " 33.33% documented\n"

    @output = StringIO.new
    @stats = CLI::Stats.new(false)
    allow(@stats).to receive(:support_rdoc_document_file!).and_return([])
    allow(@stats).to receive(:yardopts).and_return([])
    allow(log).to receive(:puts) {|*args| @output << args.join("\n") << "\n" }
  end

  it "lists undocumented objects with --list-undoc when there are undocumented objects" do
    @stats.run('--list-undoc')
    expect(@output.string).to eq <<-eof
#{@main_stats}
Undocumented Objects:

(in file: (stdin))
A
A#foo
A::CONST
B
eof
  end

  it "lists no undocumented objects with --list-undoc when there is nothing undocumented" do
    Registry.clear
    YARD.parse_string <<-eof
      # documentation
      def foo; end
    eof
    @stats.run('--list-undoc')
    expect(@output.string).to eq "Files:           1\n" \
                                 "Modules:         0 (    0 undocumented)\n" \
                                 "Classes:         0 (    0 undocumented)\n" \
                                 "Constants:       0 (    0 undocumented)\n" \
                                 "Attributes:      0 (    0 undocumented)\n" \
                                 "Methods:         1 (    0 undocumented)\n" \
                                 " 100.00% documented\n"
  end

  it "lists undocumented objects in compact mode with --list-undoc --compact" do
    @stats.run('--list-undoc', '--compact')
    expect(@output.string).to eq <<-eof
#{@main_stats}
Undocumented Objects:
A            ((stdin):1)
A#foo        ((stdin):4)
A::CONST     ((stdin):2)
B            ((stdin):11)
eof
  end

  it "still lists stats with --quiet" do
    @stats.run('--quiet')
    expect(@output.string).to eq @main_stats
  end

  it "ignores everything with --no-public" do
    @stats.run('--no-public')
    expect(@output.string).to eq(
      "Files:           0\n" \
      "Modules:         0 (    0 undocumented)\n" \
      "Classes:         0 (    0 undocumented)\n" \
      "Constants:       0 (    0 undocumented)\n" \
      "Attributes:      0 (    0 undocumented)\n" \
      "Methods:         0 (    0 undocumented)\n" \
      " 100.00% documented\n"
    )
  end
end
