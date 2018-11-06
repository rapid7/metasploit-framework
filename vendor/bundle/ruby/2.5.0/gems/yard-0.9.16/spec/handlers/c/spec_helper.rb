# frozen_string_literal: true

def parse(src, file = '(stdin)')
  YARD::Registry.clear
  parser = YARD::Parser::SourceParser.new(:c)
  parser.file = file
  parser.parse(StringIO.new(src))
end

def parse_init(src)
  YARD::Registry.clear
  YARD.parse_string("void Init_Foo() {\n#{src}\n}", :c)
end

def parse_multi_file_init(*srcs)
  YARD::Registry.clear
  srcs = srcs.map {|src| StringIO.new("void Init_Foo() {\n#{src}\n}") }
  orig_type = YARD::Parser::SourceParser.parser_type
  YARD::Parser::SourceParser.parser_type = :c
  YARD::Parser::OrderedParser.new(OpenStruct.new, srcs).parse
ensure
  YARD::Parser::SourceParser.parser_type = orig_type
end
