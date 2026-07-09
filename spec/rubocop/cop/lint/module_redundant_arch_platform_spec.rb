# frozen_string_literal: true

require 'spec_helper'
require 'rubocop/cop/lint/module_redundant_arch_platform'

RSpec.describe RuboCop::Cop::Lint::ModuleRedundantArchPlatform do
  subject(:cop) { described_class.new(config) }
  let(:empty_rubocop_config) { {} }
  let(:config) { RuboCop::Config.new(empty_rubocop_config) }

  context 'when Arch is redundant' do
    it 'registers an offense and autocorrects' do
      expect_offense(<<~RUBY)
        class DummyModule
          def initialize(info = {})
            super(
              update_info(
                info,
                'Name' => 'Test module',
                'Description' => 'A test module',
                'Author' => ['example'],
                'License' => MSF_LICENSE,
                'Arch' => ARCH_X86,
                ^^^^^^ Remove top-level `Arch` as it is already defined in all `Targets`
                'Targets' => [
                  ['Windows x86', { 'Arch' => ARCH_X86 }],
                  ['Windows x64', { 'Arch' => ARCH_X64 }]
                ]
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
                'Name' => 'Test module',
                'Description' => 'A test module',
                'Author' => ['example'],
                'License' => MSF_LICENSE,
                'Targets' => [
                  ['Windows x86', { 'Arch' => ARCH_X86 }],
                  ['Windows x64', { 'Arch' => ARCH_X64 }]
                ]
              )
            )
          end
        end
      RUBY
    end
  end

  context 'when Platform is redundant' do
    it 'registers an offense and autocorrects' do
      expect_offense(<<~RUBY)
        class DummyModule
          def initialize(info = {})
            super(
              update_info(
                info,
                'Name' => 'Test module',
                'Description' => 'A test module',
                'Author' => ['example'],
                'License' => MSF_LICENSE,
                'Platform' => 'win',
                ^^^^^^^^^^ Remove top-level `Platform` as it is already defined in all `Targets`
                'Targets' => [
                  ['Windows x86', { 'Platform' => 'win', 'Arch' => ARCH_X86 }],
                  ['Windows x64', { 'Platform' => 'win', 'Arch' => ARCH_X64 }]
                ]
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
                'Name' => 'Test module',
                'Description' => 'A test module',
                'Author' => ['example'],
                'License' => MSF_LICENSE,
                'Targets' => [
                  ['Windows x86', { 'Platform' => 'win', 'Arch' => ARCH_X86 }],
                  ['Windows x64', { 'Platform' => 'win', 'Arch' => ARCH_X64 }]
                ]
              )
            )
          end
        end
      RUBY
    end
  end

  context 'when both Arch and Platform are redundant' do
    it 'registers offenses for both and autocorrects' do
      expect_offense(<<~RUBY)
        class DummyModule
          def initialize(info = {})
            super(
              update_info(
                info,
                'Name' => 'Test module',
                'Description' => 'A test module',
                'Author' => ['example'],
                'License' => MSF_LICENSE,
                'Platform' => 'win',
                ^^^^^^^^^^ Remove top-level `Platform` as it is already defined in all `Targets`
                'Arch' => ARCH_X86,
                ^^^^^^ Remove top-level `Arch` as it is already defined in all `Targets`
                'Targets' => [
                  ['Windows x86', { 'Platform' => 'win', 'Arch' => ARCH_X86 }],
                  ['Windows x64', { 'Platform' => 'win', 'Arch' => ARCH_X64 }]
                ]
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
                'Name' => 'Test module',
                'Description' => 'A test module',
                'Author' => ['example'],
                'License' => MSF_LICENSE,
                'Targets' => [
                  ['Windows x86', { 'Platform' => 'win', 'Arch' => ARCH_X86 }],
                  ['Windows x64', { 'Platform' => 'win', 'Arch' => ARCH_X64 }]
                ]
              )
            )
          end
        end
      RUBY
    end
  end

  context 'when Arch is not redundant' do
    it 'does not register an offense when not all targets define Arch' do
      expect_no_offenses(<<~RUBY)
        class DummyModule
          def initialize(info = {})
            super(
              update_info(
                info,
                'Name' => 'Test module',
                'Description' => 'A test module',
                'Author' => ['example'],
                'License' => MSF_LICENSE,
                'Arch' => ARCH_X86,
                'Targets' => [
                  ['Windows x86', { 'Arch' => ARCH_X86 }],
                  ['Automatic', {}]
                ]
              )
            )
          end
        end
      RUBY
    end

    it 'does not register an offense when there are no Targets' do
      expect_no_offenses(<<~RUBY)
        class DummyModule
          def initialize(info = {})
            super(
              update_info(
                info,
                'Name' => 'Test module',
                'Description' => 'A test module',
                'Author' => ['example'],
                'License' => MSF_LICENSE,
                'Arch' => ARCH_X86,
                'Platform' => 'win'
              )
            )
          end
        end
      RUBY
    end
  end

  context 'when Platform is not redundant' do
    it 'does not register an offense when not all targets define Platform' do
      expect_no_offenses(<<~RUBY)
        class DummyModule
          def initialize(info = {})
            super(
              update_info(
                info,
                'Name' => 'Test module',
                'Description' => 'A test module',
                'Author' => ['example'],
                'License' => MSF_LICENSE,
                'Platform' => 'win',
                'Targets' => [
                  ['Windows x86', { 'Platform' => 'win', 'Arch' => ARCH_X86 }],
                  ['Linux x64', { 'Arch' => ARCH_X64 }]
                ]
              )
            )
          end
        end
      RUBY
    end
  end

  context 'with nested update_info form' do
    it 'registers an offense with the nested super form' do
      expect_offense(<<~RUBY)
        class DummyModule
          def initialize(info = {})
            super(update_info(
              info,
              'Name' => 'Test module',
              'Description' => 'A test module',
              'Author' => ['example'],
              'License' => MSF_LICENSE,
              'Arch' => ARCH_X86,
              ^^^^^^ Remove top-level `Arch` as it is already defined in all `Targets`
              'Targets' => [
                ['Windows x86', { 'Arch' => ARCH_X86 }],
                ['Windows x64', { 'Arch' => ARCH_X64 }]
              ]
            ))
          end
        end
      RUBY

      expect_correction(<<~RUBY)
        class DummyModule
          def initialize(info = {})
            super(update_info(
              info,
              'Name' => 'Test module',
              'Description' => 'A test module',
              'Author' => ['example'],
              'License' => MSF_LICENSE,
              'Targets' => [
                ['Windows x86', { 'Arch' => ARCH_X86 }],
                ['Windows x64', { 'Arch' => ARCH_X64 }]
              ]
            ))
          end
        end
      RUBY
    end
  end

  context 'with single target' do
    it 'registers an offense when the single target defines Arch and Platform' do
      expect_offense(<<~RUBY)
        class DummyModule
          def initialize(info = {})
            super(
              update_info(
                info,
                'Name' => 'Test module',
                'Description' => 'A test module',
                'Author' => ['example'],
                'License' => MSF_LICENSE,
                'Platform' => 'win',
                ^^^^^^^^^^ Remove top-level `Platform` as it is already defined in all `Targets`
                'Arch' => [ARCH_X86, ARCH_X64],
                ^^^^^^ Remove top-level `Arch` as it is already defined in all `Targets`
                'Targets' => [
                  ['Windows', { 'Platform' => 'win', 'Arch' => [ARCH_X86, ARCH_X64] }]
                ]
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
                'Name' => 'Test module',
                'Description' => 'A test module',
                'Author' => ['example'],
                'License' => MSF_LICENSE,
                'Targets' => [
                  ['Windows', { 'Platform' => 'win', 'Arch' => [ARCH_X86, ARCH_X64] }]
                ]
              )
            )
          end
        end
      RUBY
    end
  end

  context 'with merge_info' do
    it 'registers an offense for merge_info call' do
      expect_offense(<<~RUBY)
        class DummyModule
          def initialize(info = {})
            super(
              merge_info(
                info,
                'Name' => 'Test module',
                'Description' => 'A test module',
                'Author' => ['example'],
                'License' => MSF_LICENSE,
                'Arch' => ARCH_X86,
                ^^^^^^ Remove top-level `Arch` as it is already defined in all `Targets`
                'Targets' => [
                  ['Windows x86', { 'Arch' => ARCH_X86 }]
                ]
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
                'Name' => 'Test module',
                'Description' => 'A test module',
                'Author' => ['example'],
                'License' => MSF_LICENSE,
                'Targets' => [
                  ['Windows x86', { 'Arch' => ARCH_X86 }]
                ]
              )
            )
          end
        end
      RUBY
    end
  end

  context 'with empty targets array' do
    it 'does not register an offense' do
      expect_no_offenses(<<~RUBY)
        class DummyModule
          def initialize(info = {})
            super(
              update_info(
                info,
                'Name' => 'Test module',
                'Description' => 'A test module',
                'Author' => ['example'],
                'License' => MSF_LICENSE,
                'Arch' => ARCH_X86,
                'Platform' => 'win',
                'Targets' => []
              )
            )
          end
        end
      RUBY
    end
  end

  context 'when target has no options hash' do
    it 'does not register an offense for targets without hash element' do
      expect_no_offenses(<<~RUBY)
        class DummyModule
          def initialize(info = {})
            super(
              update_info(
                info,
                'Name' => 'Test module',
                'Description' => 'A test module',
                'Author' => ['example'],
                'License' => MSF_LICENSE,
                'Arch' => ARCH_X86,
                'Platform' => 'win',
                'Targets' => [
                  ['Automatic']
                ]
              )
            )
          end
        end
      RUBY
    end
  end
end
