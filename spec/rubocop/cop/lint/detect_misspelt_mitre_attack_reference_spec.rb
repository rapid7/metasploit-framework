# frozen_string_literal: true

require 'spec_helper'
require 'rubocop/cop/lint/detect_misspelt_mitre_attack_reference'

RSpec.describe RuboCop::Cop::Lint::DetectMisspeltMitreAttackReference, :config do
  subject(:cop) { described_class.new(config) }

  let(:config) { RuboCop::Config.new }

  it 'registers an offense for misspelt ATT&CK in References in initialize' do
    expect_offense(<<~RUBY)
      def initialize(info = {})
        super(update_info(info,
          'References'     =>
            [
              [ 'ATTACK', Mitre::Attack::Technique::T1021_002_SMB_WINDOWS_ADMIN_SHARES ],
                ^^^^^^^^ Lint/DetectMisspeltMitreAttackReference: Mispelt ATT&CK reference. Use 'ATT&CK' instead.
              [ 'ATT&CK', Mitre::Attack::Technique::T1059_001_POWERSHELL ]
            ]
        ))
      end
    RUBY
  end

  it 'autocorrects misspelt ATT&CK to ATT&CK' do
    corrected = autocorrect_source(<<~RUBY)
      def initialize(info = {})
        super(update_info(info,
          'References'     =>
            [
              [ 'ATTACK', Mitre::Attack::Technique::T1021_002_SMB_WINDOWS_ADMIN_SHARES ],
              [ 'ATT&CK', Mitre::Attack::Technique::T1059_001_POWERSHELL ]
            ]
        ))
      end
    RUBY
    expect(corrected).to include("[ 'ATT&CK', Mitre::Attack::Technique::T1021_002_SMB_WINDOWS_ADMIN_SHARES ]")
  end

  it 'does not register an offense for correct ATT&CK' do
    expect_no_offenses(<<~RUBY)
      def initialize(info = {})
        super(update_info(info,
          'References'     =>
            [
              [ 'ATT&CK', Mitre::Attack::Technique::T1021_002_SMB_WINDOWS_ADMIN_SHARES ]
            ]
        ))
      end
    RUBY
  end

  it 'does not register an offense outside initialize' do
    expect_no_offenses(<<~RUBY)
      def foo
        [ 'ATTACK', Mitre::Attack::Technique::T1021_002_SMB_WINDOWS_ADMIN_SHARES ]
      end
    RUBY
  end
end
