# frozen_string_literal: true
require 'spec_helper'
require 'rubocop/cop/layout/module_description_indentation'

RSpec.describe RuboCop::Cop::Layout::ModuleDescriptionIndentation do
  subject(:cop) { described_class.new(config) }
  let(:config) do
    RuboCop::Config.new(
      'Layout/IndentationWidth' => {
        'Width' => indentation_width
      })
  end
  let(:indentation_width) { 2 }

  it 'accepts descriptions being on one line being on a new line' do
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

  it 'accepts descriptions correctly formatted using %q syntax' do
    expect_no_offenses(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name'           => 'Simple module name',
              'Description'    => %q{
                Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque efficitur pulvinar arcu eget ultrices.
                Vestibulum at risus at nisi convallis laoreet a sed libero. Nam vestibulum euismod dictum. Pellentesque
                eu nunc vitae mi volutpat viverra in id ipsum. Maecenas fermentum condimentum dapibus.
              },
              'Author'        => [
                'example1',
                'example2'
              ],
              'License'       => MSF_LICENSE,
              'Platform'      => 'win',
              'Arch'          => ARCH_X86,
            )
          )
        end
      end
    RUBY
  end

  it 'registers an offense when a multiline description requires a preceeding new line' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name'           => 'Simple module name',
              'Description'    => %q(Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque efficitur pulvinar arcu eget ultrices.
            Vestibulum at risus at nisi convallis laoreet a sed libero. Nam vestibulum euismod dictum. Pellentesque
            eu nunc vitae mi volutpat viverra in id ipsum. Maecenas fermentum condimentum dapibus.),
                                                                                                  ^ Module descriptions should be properly aligned to the 'Description' key, and within %q{ ... }
              'Author'        => [
                'example1',
                'example2'
              ],
              'License'       => MSF_LICENSE,
              'Platform'      => 'win',
              'Arch'          => ARCH_X86,
            )
          )
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name'           => 'Simple module name',
              'Description'    => %q{
                Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque efficitur pulvinar arcu eget ultrices.
                Vestibulum at risus at nisi convallis laoreet a sed libero. Nam vestibulum euismod dictum. Pellentesque
                eu nunc vitae mi volutpat viverra in id ipsum. Maecenas fermentum condimentum dapibus.
              },
              'Author'        => [
                'example1',
                'example2'
              ],
              'License'       => MSF_LICENSE,
              'Platform'      => 'win',
              'Arch'          => ARCH_X86,
            )
          )
        end
      end
    RUBY
  end

  it 'registers an offense when a multiline description requires a preceeding new line' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name'           => 'Simple module name',
              'Description'    => "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque efficitur pulvinar arcu eget ultrices.
            Vestibulum at risus at nisi convallis laoreet a sed libero. Nam vestibulum euismod dictum. Pellentesque
            eu nunc vitae mi volutpat viverra in id ipsum. Maecenas fermentum condimentum dapibus.",
                                                                                                  ^ Module descriptions should be properly aligned to the 'Description' key, and within %q{ ... }
              'Author'        => [
                'example1',
                'example2'
              ],
              'License'       => MSF_LICENSE,
              'Platform'      => 'win',
              'Arch'          => ARCH_X86,
            )
          )
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name'           => 'Simple module name',
              'Description'    => %q{
                Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque efficitur pulvinar arcu eget ultrices.
                Vestibulum at risus at nisi convallis laoreet a sed libero. Nam vestibulum euismod dictum. Pellentesque
                eu nunc vitae mi volutpat viverra in id ipsum. Maecenas fermentum condimentum dapibus.
              },
              'Author'        => [
                'example1',
                'example2'
              ],
              'License'       => MSF_LICENSE,
              'Platform'      => 'win',
              'Arch'          => ARCH_X86,
            )
          )
        end
      end
    RUBY
  end

  it 'registers an offense when descriptions are incorrectly indented' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name'           => 'Simple module name',
              'Description'    => %q(
            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque efficitur pulvinar arcu eget ultrices.
            Vestibulum at risus at nisi convallis laoreet a sed libero. Nam vestibulum euismod dictum. Pellentesque
            eu nunc vitae mi volutpat viverra in id ipsum. Maecenas fermentum condimentum dapibus.
            ),
            ^ Module descriptions should be properly aligned to the 'Description' key, and within %q{ ... }
              'Author'        => [
                'example1',
                'example2'
              ],
              'License'       => MSF_LICENSE,
              'Platform'      => 'win',
              'Arch'          => ARCH_X86,
            )
          )
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name'           => 'Simple module name',
              'Description'    => %q{
                Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque efficitur pulvinar arcu eget ultrices.
                Vestibulum at risus at nisi convallis laoreet a sed libero. Nam vestibulum euismod dictum. Pellentesque
                eu nunc vitae mi volutpat viverra in id ipsum. Maecenas fermentum condimentum dapibus.
              },
              'Author'        => [
                'example1',
                'example2'
              ],
              'License'       => MSF_LICENSE,
              'Platform'      => 'win',
              'Arch'          => ARCH_X86,
            )
          )
        end
      end
    RUBY
  end

  it 'registers an offense when descriptions are incorrectly indented with the merge_info function' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            merge_info(
              info,
              'Name'           => 'Simple module name',
              'Description'    => %q(
            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque efficitur pulvinar arcu eget ultrices.
            Vestibulum at risus at nisi convallis laoreet a sed libero. Nam vestibulum euismod dictum. Pellentesque
            eu nunc vitae mi volutpat viverra in id ipsum. Maecenas fermentum condimentum dapibus.
            ),
            ^ Module descriptions should be properly aligned to the 'Description' key, and within %q{ ... }
              'Author'        => [
                'example1',
                'example2'
              ],
              'License'       => MSF_LICENSE,
              'Platform'      => 'win',
              'Arch'          => ARCH_X86,
            )
          )
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            merge_info(
              info,
              'Name'           => 'Simple module name',
              'Description'    => %q{
                Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque efficitur pulvinar arcu eget ultrices.
                Vestibulum at risus at nisi convallis laoreet a sed libero. Nam vestibulum euismod dictum. Pellentesque
                eu nunc vitae mi volutpat viverra in id ipsum. Maecenas fermentum condimentum dapibus.
              },
              'Author'        => [
                'example1',
                'example2'
              ],
              'License'       => MSF_LICENSE,
              'Platform'      => 'win',
              'Arch'          => ARCH_X86,
            )
          )
        end
      end
    RUBY
  end

  it 'registers an offense when there is additional whitespace' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            merge_info(
              info,
              'Name'           => 'Simple module name',
              'Description'    => %q(



            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque efficitur pulvinar arcu eget ultrices.
            Vestibulum at risus at nisi convallis laoreet a sed libero. Nam vestibulum euismod dictum. Pellentesque
            eu nunc vitae mi volutpat viverra in id ipsum. Maecenas fermentum condimentum dapibus.



            ),
            ^ Module descriptions should be properly aligned to the 'Description' key, and within %q{ ... }
              'Author'        => [
                'example1',
                'example2'
              ],
              'License'       => MSF_LICENSE,
              'Platform'      => 'win',
              'Arch'          => ARCH_X86,
            )
          )
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            merge_info(
              info,
              'Name'           => 'Simple module name',
              'Description'    => %q{
                Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque efficitur pulvinar arcu eget ultrices.
                Vestibulum at risus at nisi convallis laoreet a sed libero. Nam vestibulum euismod dictum. Pellentesque
                eu nunc vitae mi volutpat viverra in id ipsum. Maecenas fermentum condimentum dapibus.
              },
              'Author'        => [
                'example1',
                'example2'
              ],
              'License'       => MSF_LICENSE,
              'Platform'      => 'win',
              'Arch'          => ARCH_X86,
            )
          )
        end
      end
    RUBY
  end

  it 'registers an offense when the wrong literal type is used' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name'           => 'Simple module name',
              'Description'    => %Q(
                Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque efficitur pulvinar arcu eget ultrices.
                Vestibulum at risus at nisi convallis laoreet a sed libero. Nam vestibulum euismod dictum. Pellentesque
                eu nunc vitae mi volutpat viverra in id ipsum. Maecenas fermentum condimentum dapibus.
              ),
              ^ Module descriptions should be properly aligned to the 'Description' key, and within %q{ ... }
              'Author'        => [
                'example1',
                'example2'
              ],
              'License'       => MSF_LICENSE,
              'Platform'      => 'win',
              'Arch'          => ARCH_X86,
            )
          )
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name'           => 'Simple module name',
              'Description'    => %q{
                Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque efficitur pulvinar arcu eget ultrices.
                Vestibulum at risus at nisi convallis laoreet a sed libero. Nam vestibulum euismod dictum. Pellentesque
                eu nunc vitae mi volutpat viverra in id ipsum. Maecenas fermentum condimentum dapibus.
              },
              'Author'        => [
                'example1',
                'example2'
              ],
              'License'       => MSF_LICENSE,
              'Platform'      => 'win',
              'Arch'          => ARCH_X86,
            )
          )
        end
      end
    RUBY
  end
end
