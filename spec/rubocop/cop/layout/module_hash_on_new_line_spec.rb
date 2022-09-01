# frozen_string_literal: true
require 'spec_helper'
require 'rubocop/cop/layout/module_hash_on_new_line'

RSpec.describe RuboCop::Cop::Layout::ModuleHashOnNewLine do
  subject(:cop) { described_class.new(config) }
  let(:config) do
    RuboCop::Config.new(
      'Layout/IndentationWidth' => {
        'Width' => indentation_width
      })
  end
  let(:indentation_width) { 2 }

  it 'accepts update_info being on a new line' do
    expect_no_offenses(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name'          => 'Simple module name',
              'Description'   => 'Lorem ipsum dolor sit amet',
              'Author'        => [ 'example1', 'example2' ],
              'License'       => MSF_LICENSE,
              'Platform'      => 'win',
              'Arch'          => ARCH_X86,
            )
          )
        end
      end
    RUBY
  end

  it 'registers an offence when update_info is not on its own line' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(update_info(info,
                            ^^^^ info should start on its own line
                           ^ update_info should start on its own line
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author'        => [ 'example1', 'example2' ],
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            ))
            ^ A new line is missing
        end
      end
    RUBY
  end

  it 'still registers offenses if register_options is present' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(update_info(info,
                            ^^^^ info should start on its own line
                           ^ update_info should start on its own line
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author'        => [ 'example1', 'example2' ],
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            ))
            ^ A new line is missing
            register_options([])
        end
      end
    RUBY
  end

  it 'reports only one error if info is already on its own line' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(update_info(
                           ^ update_info should start on its own line
                info,
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author'        => [ 'example1', 'example2' ],
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            )
          )
          register_options([])
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
                info,
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author'        => [ 'example1', 'example2' ],
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            )
          )
          register_options([])
        end
      end
    RUBY
  end

  it 'ensures merge_info functions are on their own lines' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(merge_info(
                          ^ merge_info should start on its own line
                info,
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author'        => [ 'example1', 'example2' ],
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            )
          )
          register_options([])
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            merge_info(
                info,
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author'        => [ 'example1', 'example2' ],
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            )
          )
          register_options([])
        end
      end
    RUBY
  end

  it 'reports an error if update_info and info are on the same line' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
              update_info(info,
                          ^^^^ info should start on its own line
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author'        => [ 'example1', 'example2' ],
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            ))
            ^ A new line is missing
          register_options([])
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
              update_info(
                info,
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author'        => [ 'example1', 'example2' ],
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            )
          )
          register_options([])
        end
      end
    RUBY
  end

  it 'still registers offenses if register_options is present' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(update_info(info,
                            ^^^^ info should start on its own line
                           ^ update_info should start on its own line
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author'        => [ 'example1', 'example2' ],
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            ))
            ^ A new line is missing
          register_options([])
        end
      end
    RUBY
  end
end
