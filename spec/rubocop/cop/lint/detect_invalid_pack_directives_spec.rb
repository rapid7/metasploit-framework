require 'spec_helper'
require 'rubocop/cop/lint/detect_invalid_pack_directives'

RSpec.describe RuboCop::Cop::Lint::DetectInvalidPackDirectives do
  subject(:cop) { described_class.new(config) }
  let(:empty_rubocop_config) { {} }
  let(:config) { RuboCop::Config.new(empty_rubocop_config) }
  let(:pack_directive) { "Q<" }
  let(:pack_amount) { 2 }
  let(:endian) {:little}
  let(:packstr) {(endian == :little) ? 'v' : 'n'}

  context 'when passed an unknown pack/unpacks directive' do
    it 'detects the invalid directive' do
      expect_offense(<<~RUBY)
        [10].pack('_I')
                   ^ unknown pack directive '_' in '_I'
      RUBY
    end

    it 'detects the invalid directive' do
      expect_offense(<<~RUBY)
        [10].pack('<L<L<Q<Q<Q<La*<L<Q<Q<Q<Q<Q<Q<L<L<Q<L<L')
                   ^ unknown pack directive '<' in '<L<L<Q<Q<Q<La*<L<Q<Q<Q<Q<Q<Q<L<L<Q<L<L'
      RUBY
    end

    it 'detects the invalid directive' do
      expect_offense(<<~RUBY)
        [10].pack('<123456')
                   ^ unknown pack directive '<' in '<123456'
      RUBY
    end

    it 'detects the invalid directive' do
      expect_offense(<<~RUBY)
        [10].pack('<')
                   ^ unknown pack directive '<' in '<'
      RUBY
    end

    it 'detects the invalid directive' do
      expect_offense(<<~RUBY)
        [10].pack('<s')
                   ^ unknown pack directive '<' in '<s'
      RUBY
    end

    it 'detects the invalid directive' do
      expect_offense(<<~RUBY)
        [0x0123456789ABCDEF, 'foo'].pack('<Qa*')
                                          ^ unknown pack directive '<' in '<Qa*'
      RUBY
    end

    it 'detects the invalid directive' do
      expect_offense(<<~RUBY)
        [112].pack('<I')
                    ^ unknown pack directive '<' in '<I'
      RUBY
    end

    it 'detects the invalid directive' do
      expect_offense(<<~RUBY)
        [1].pack('<ISSSSI')
                  ^ unknown pack directive '<' in '<ISSSSI'
      RUBY
    end

    it 'detects the invalid directive' do
      expect_offense(<<~RUBY)
        [200].pack('<L')
                    ^ unknown pack directive '<' in '<L'
      RUBY
    end

    it 'detects the invalid directive' do
      expect_offense(<<~RUBY)
        [400].pack('<S<S')
                    ^ unknown pack directive '<' in '<S<S'
      RUBY
    end

    it 'detects the invalid directive' do
      expect_offense(<<~RUBY)
        "foo".unpack("*V")
                      ^ unknown pack directive '*' in '*V'
      RUBY
    end

    it 'detects the invalid directive' do
      expect_offense(<<~RUBY)
        "foo".unpack("D<")
                       ^ '<' allowed only after types sSiIlLqQjJ
      RUBY
    end

    it 'detects the invalid directive' do
      expect_offense(<<~RUBY)
        "foo".unpack(%q{D<})
                         ^ '<' allowed only after types sSiIlLqQjJ
      RUBY
    end

    it 'detects the invalid directive' do
      expect_offense(<<~'RUBY')
        "foo".unpack("\tD<")
                         ^ '<' allowed only after types sSiIlLqQjJ
      RUBY
    end
  end

  context 'when passed multiline strings with invalid pack/unpacks directives' do
    it 'ignores comments in the format string and detects the invalid directive' do
      expect_offense(<<~RUBY)
        [9.3, 4.7].pack <<~EOF
          # The first decimal value
          D # first inline comment
          # The second decimal value
          D< # The second inline comment
           ^ '<' allowed only after types sSiIlLqQjJ
          # Final comment
        EOF
      RUBY
    end

    it 'ignores comments in the format string and detects the invalid directive' do
      expect_offense(<<~RUBY)
        [9.3, 4.7].pack <<~EOF
              # The first decimal value
              D # first inline comment
              # The second decimal value
              D< # The second inline comment
               ^ '<' allowed only after types sSiIlLqQjJ
              # Final comment
        EOF
      RUBY
    end

    it 'ignores comments in the format string and detects the invalid directive' do
      expect_offense(<<~RUBY)
        [9.3, 4.7].pack <<~EOF
          # The first decimal value
            D # first inline comment
          # The second decimal value
          D< # The second inline comment
           ^ '<' allowed only after types sSiIlLqQjJ
          # Final comment
        EOF
      RUBY
    end

    it 'ignores comments in the format string and detects the invalid directive' do
      expect_offense(<<~'RUBY')
        [1,2,3].pack("D# some comment \nD# some comment \n# some comment \nD>")
                                                                            ^ '>' allowed only after types sSiIlLqQjJ
      RUBY
    end

    it 'ignores comments in the format string and detects the invalid directive' do
      expect_offense(<<~'RUBY')
        [1,2,3].pack("D># some comment \nD# some comment \n# some comment \nD")
                       ^ '>' allowed only after types sSiIlLqQjJ
      RUBY
    end

    it 'ignores comments in the format string and detects the invalid directive' do
      expect_offense(<<~'RUBY')
        [9.3, 4.7].pack("D# some comment \nD<")
                                            ^ '<' allowed only after types sSiIlLqQjJ
      RUBY
    end

    it 'raises an offense' do
      expect_offense(<<-'RUBY')
        [10].pack(
          "Q" \
          "D<"
            ^ '<' allowed only after types sSiIlLqQjJ
        )
      RUBY
    end
  end

  context 'when passed string interpolation' do
    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [1, 2].pack("@1#{'XV' * (2 * 2)}")
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<-'RUBY')
        [9, 4].pack("@1#{'XV' * (pack_amount * pack_amount)}")
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<-'RUBY')
        [9, 4].pack("I<c#{pack_amount}")
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<-'RUBY')
        "\t\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00".unpack("#{pack_directive}@1")
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<-'RUBY')
        options[idx, 4].unpack("#{packstr}2")
      RUBY
    end
  end

  it 'raises an offense' do
    expect_no_offenses(<<-'RUBY')
        "\t\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00".unpack("#{pack_directive}*")
    RUBY
  end

  context 'when passed valid pack/unpacks directives' do
    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        "a\x10\x10\x10".unpack('nCCnnQ>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        ['abc'].pack('h3')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [1, 2].pack("C@3C")
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        ['a' * 123].pack('h123')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        ['abc', 'a'].pack('h3h')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('C')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('S')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('L')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('Q')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('J')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('c')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('s')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('l')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('q')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('j')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('S_')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('S!')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('I')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('J')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('I_')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('I!')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('L_')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('L!')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('Q_')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('Q!')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('J!')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('s_')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('s!')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('i')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('i_')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('i!')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('l')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('l!')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('q_')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('q!')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('j!')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('S>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('s>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('S!>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('s!>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('L>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('l>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('L!>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('l!>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('I!>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('i!>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('Q>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('q>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('Q!>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('q!>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('J>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('j>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('J!>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('j!>')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('S<')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('s<')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('S!<')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('s!<')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('L<')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('l<')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('L!<')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('l!<')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('I!<')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('i!<')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('Q<')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('q<')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('Q!<')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('q!<')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('J<')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('j<')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('J!<')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('j!<')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('n')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('N')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('v')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('V')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('U')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack('w')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10.10].pack('D')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10.10].pack('d')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10.10].pack('F')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10.10].pack('f')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10.10].pack('E')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10.10].pack('e')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10.10].pack('G')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10.10].pack('g')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        ['test'].pack('A')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        ['test'].pack('a')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        ['test'].pack('Z')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        ['test'].pack('B')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        ['test'].pack('b')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        ['test'].pack('H')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        ['test'].pack('h')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        ['test'].pack('u')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        ['test'].pack('M')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        ['test'].pack('m')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        ['test'].pack('p')
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        ['test'].pack('P')
      RUBY
    end
  end

  context 'when passed multiline strings with valid pack/unpacks directives' do
    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [9.3, 4.7].pack <<~EOF
          # The first decimal value
          D # first inline comment
          # The second decimal value
          S< # The second inline comment
          # Final comment
        EOF
      RUBY
    end

    it 'does not raise an offence' do
      expect_no_offenses(<<~RUBY)
        [10].pack(
          "Q" \
          "L"
        )
      RUBY
    end

    it 'raises an offense' do
      expect_no_offenses(<<-'RUBY')
        [10].pack(
          "Q" \
          "<L"
        )
      RUBY
    end

    it 'ignores comments in the format string and detects the invalid directive' do
      expect_no_offenses(<<~RUBY)
        [9.3, 4.7].pack("D# some comment S<")
      RUBY
    end
  end
end
