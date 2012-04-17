require 'spec_helper'

BENCHMARK = false
METAGRAMMAR_PATH = File.expand_path('../../../lib/treetop/compiler/metagrammar.treetop', __FILE__)

module CircularCompilationSpec
  describe "a parser for the metagrammar" do
    attr_reader :parser
    
    before do
      @parser = Treetop::Compiler::MetagrammarParser.new
    end
    
    it "can parse the metagrammar.treetop whence it was generated" do
      File.open(METAGRAMMAR_PATH, 'r') do |f|
        metagrammar_source = f.read
        result = parser.parse(metagrammar_source)
        result.should_not be_nil

        # generated_parser = result.compile
        # Object.class_eval(generated_parser)
        # parser_2 = Treetop::Compiler::MetagrammarParser.new
        # optionally_benchmark do
        #   result = parser_2.parse(metagrammar_source)
        #   result.should_not be_nil
        # end
      end
    end
  end
end
