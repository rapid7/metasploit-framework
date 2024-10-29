# frozen_string_literal: true

require 'spec_helper'
require 'rubocop/cop/layout/extra_spacing_with_bindata_ignored'

RSpec.describe RuboCop::Cop::Layout::ExtraSpacingWithBinDataIgnored do
  subject(:cop) { described_class.new(config) }
  let(:config) do
    RuboCop::Config.new(
      'Layout/ExtraSpacingWithBinDataIgnored' => {
        'AllowForAlignment' => false,
        'AllowBeforeTrailingComments' => true,
        'ForceEqualSignAlignment' => false
      }
    )
  end

  it 'registers an offense and corrects alignment' do
    expect_offense(<<~RUBY)
      uint8    :foo
           ^^^ Unnecessary spacing detected.
      uint16   :bar
            ^^ Unnecessary spacing detected.
    RUBY

    expect_correction(<<~RUBY)
      uint8 :foo
      uint16 :bar
    RUBY
  end

  it 'ignores offenses within BinData objects' do
    expect_no_offenses(<<~RUBY)
      class Foo < BinData::Record
        uint8    :foo
        uint16   :bar
      end

      class Bar < BinData::Array
        BAR_SUCCESS           = 0x0001
        BAR_SOME_FLAG         = 0x0010

        choice                   :member_value, selection: -> { selection_routine(index) } do
          record                  Types::Record
          boolean                 Enums::PrimitiveTypeEnum[:Boolean]
          uint8                   Enums::PrimitiveTypeEnum[:Byte]
          #???                    Enums::PrimitiveTypeEnum[:Char] # todo: implement this primitive type
          length_prefixed_string  Enums::PrimitiveTypeEnum[:Decimal]
          double                  Enums::PrimitiveTypeEnum[:Double]
          int16                   Enums::PrimitiveTypeEnum[:Int16]
          int32                   Enums::PrimitiveTypeEnum[:Int32]
          int64                   Enums::PrimitiveTypeEnum[:Int64]
          int8                    Enums::PrimitiveTypeEnum[:SByte]
          float                   Enums::PrimitiveTypeEnum[:Single]
          int64                   Enums::PrimitiveTypeEnum[:TimeSpan]
          date_time               Enums::PrimitiveTypeEnum[:DateTime]
          uint16                  Enums::PrimitiveTypeEnum[:UInt16]
          uint32                  Enums::PrimitiveTypeEnum[:UInt32]
          uint64                  Enums::PrimitiveTypeEnum[:UInt64]
          null                    Enums::PrimitiveTypeEnum[:Null]
          length_prefixed_string  Enums::PrimitiveTypeEnum[:String]
        end
      end
    RUBY
  end
end
