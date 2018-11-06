# -*- coding: utf-8 -*-
require 'spec_helper'

class Parser
  include PgArrayParser
end

describe 'PgArrayParser' do
  let!(:parser) { Parser.new }

  describe '#parse_pg_array' do
    context 'one dimensional arrays' do
      context 'empty' do
        it 'returns an empty array' do
          parser.parse_pg_array(%[{}]).should eq []
        end
      end

      context 'no strings' do
        it 'returns an array of strings' do
          parser.parse_pg_array(%[{1,2,3}]).should eq ['1','2','3']
        end
      end

      context 'NULL values' do
        it 'returns an array of strings, with nils replacing NULL characters' do
          parser.parse_pg_array(%[{1,NULL,NULL}]).should eq ['1',nil,nil]
        end
      end

      context 'quoted NULL' do
        it 'returns an array with the word NULL' do
          parser.parse_pg_array(%[{1,"NULL",3}]).should eq ['1','NULL','3']
        end
      end

      context 'strings' do
        it 'returns an array of strings when containing commas in a quoted string' do
          parser.parse_pg_array(%[{1,"2,3",4}]).should eq ['1','2,3','4']
        end

        it 'returns an array of strings when containing an escaped quote' do
          parser.parse_pg_array(%[{1,"2\\",3",4}]).should eq ['1','2",3','4']
        end

        it 'returns an array of strings when containing an escaped backslash' do
          parser.parse_pg_array(%[{1,"2\\\\",3,4}]).should eq ['1','2\\','3','4']
          parser.parse_pg_array(%[{1,"2\\\\\\",3",4}]).should eq ['1','2\\",3','4']
        end

        it 'returns an array containing empty strings' do
          parser.parse_pg_array(%[{1,"",3,""}]).should eq ['1', '', '3', '']
        end

        it 'returns an array containing unicode strings' do
          parser.parse_pg_array(%[{"Paragraph 399(b)(i) – “valid leave” – meaning"}]).should eq(['Paragraph 399(b)(i) – “valid leave” – meaning'])
        end
      end
    end

    context 'two dimensional arrays' do
      context 'empty' do
        it 'returns an empty array' do
          parser.parse_pg_array(%[{{}}]).should eq [[]]
          parser.parse_pg_array(%[{{},{}}]).should eq [[],[]]
        end
      end
      context 'no strings' do
        it 'returns an array of strings with a sub array' do
          parser.parse_pg_array(%[{1,{2,3},4}]).should eq ['1',['2','3'],'4']
        end
      end
      context 'strings' do
        it 'returns an array of strings with a sub array' do
          parser.parse_pg_array(%[{1,{"2,3"},4}]).should eq ['1',['2,3'],'4']
        end
        it 'returns an array of strings with a sub array and a quoted }' do
          parser.parse_pg_array(%[{1,{"2,}3",NULL},4}]).should eq ['1',['2,}3',nil],'4']
        end
        it 'returns an array of strings with a sub array and a quoted {' do
          parser.parse_pg_array(%[{1,{"2,{3"},4}]).should eq ['1',['2,{3'],'4']
        end
        it 'returns an array of strings with a sub array and a quoted { and escaped quote' do
          parser.parse_pg_array(%[{1,{"2\\",{3"},4}]).should eq ['1',['2",{3'],'4']
        end
        it 'returns an array of strings with a sub array with empty strings' do
          parser.parse_pg_array(%[{1,{""},4,{""}}]).should eq ['1',[''],'4',['']]
        end
      end
    end
    context 'three dimensional arrays' do
      context 'empty' do
        it 'returns an empty array' do
          parser.parse_pg_array(%[{{{}}}]).should eq [[[]]]
          parser.parse_pg_array(%[{{{},{}},{{},{}}}]).should eq [[[],[]],[[],[]]]
        end
      end
      it 'returns an array of strings with sub arrays' do
        parser.parse_pg_array(%[{1,{2,{3,4}},{NULL,6},7}]).should eq ['1',['2',['3','4']],[nil,'6'],'7']
      end
    end
  end
end
