require 'rspec'

RSpec.describe Rex::Parser::Arguments do
  let(:subject) do
    Rex::Parser::Arguments.new(
      ['-h', '--help'] => [false, 'Help banner.'],
      ['-j', '--job'] => [false, 'Run in the context of a job.'],
      '--long-flag-with-no-corresponding-short-option-name' => [false, 'A long flag with no corresponding short option name'],
      ['-o', '--options'] => [true, 'A comma separated list of options in VAR=VAL format.', '<option>'],
      ['-q', '--quiet'] => [false, 'Run the module in quiet mode with no output']
    )
  end

  describe '#parse' do
    context 'when flags are provided' do
      it 'parses a single flag correctly' do
        input = ['-h']
        expected_yields = [
          ['-h', 0, nil]
        ]
        expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
      end

      it 'parses multiple flags correctly' do
        input = ['-h', '-h', '-h']
        expected_yields = [
          ['-h', 0, nil],
          ['-h', 1, nil],
          ['-h', 2, nil],
        ]
        expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
      end

      it 'parses multiple flags combined correctly' do
        input = ['-hq']
        expected_yields = [
          ['-h', 0, nil],
          ['-q', 0, nil],
        ]
        expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
      end

      it 'ignores unknown flags' do
        input = ['-a', 'action_name']
        expected_yields = [
          # '-a' is dropped, 'action_name' is used as an argument
          [nil, 1, 'action_name'],
        ]
        expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
      end

      it 'treats combined flags that do not exist as an argument' do
        input = ['-unknown-flags']
        expected_yields = [
          [nil, 0, '-unknown-flags']
        ]
        expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
      end
    end

    it 'parses a single long flag correctly' do
      input = ['--help']
      expected_yields = [
        ['-h', 0, nil]
      ]
      expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
    end

    it 'parses multiple long flags correctly' do
      input = ['--help', '--job']
      expected_yields = [
        ['-h', 0, nil],
        ['-j', 1, nil]
      ]
      expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
    end

    it 'parses a long flag and short flag correctly' do
      input = ['--help', '-h']
      expected_yields = [
        ['-h', 0, nil],
        ['-h', 1, nil]
      ]
      expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
    end

    it 'parses a short flag when Rex Arguments are in an array correctly' do
      input = ['-o']
      expected_yields = [
        ['-o', 0, nil]
      ]
      expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
    end

    it 'parses a long flag when in arguments array correctly' do
      input = ['--options', 'option-arg']
      expected_yields = [
        ['-o', 0, 'option-arg']
      ]
      expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
    end

    it 'parses multiple long flags when in an arguments array correctly' do
      input = ['--quiet', '--options', 'sample-option']
      expected_yields = [
        ['-q', 0, nil],
        ['-o', 1, 'sample-option']
      ]
      expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
    end

    it 'parses a non-existent long flag correctly' do
      input = ['--ultra-quiet']
      expected_yields = [
        [nil, 0, '--ultra-quiet']
      ]
      expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
    end

    it 'parses a long flag that is not in an array correctly' do
      input = ['--long-flag-with-no-corresponding-short-option-name']
      expected_yields = [
        ['--long-flag-with-no-corresponding-short-option-name', 0, nil]
      ]
      expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
    end

    context 'when arguments are supplied' do
      it 'treats an ip address as an argument' do
        input = ['127.0.0.1']
        expected_yields = [
          [nil, 0, '127.0.0.1'],
        ]
        expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
      end

      it 'treats assignment as an argument' do
        input = ['foo=bar']
        expected_yields = [
          [nil, 0, 'foo=bar'],
        ]
        expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
      end

      it 'treats urls as an argument' do
        input = ['https://example.com:443/foo/bar?baz=qux&a=b']
        expected_yields = [
          [nil, 0, 'https://example.com:443/foo/bar?baz=qux&a=b'],
        ]
        expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
      end
    end
  end

  describe '#inspect' do
    it 'prints usage in a sorted order correctly' do
      expected_output = <<~EXPECTED

        OPTIONS:

            --long-flag-with-no-corresponding-short-option-name  A long flag with no corresponding short option name
            -h, --help                                           Help banner.
            -j, --job                                            Run in the context of a job.
            -o, --options <option>                               A comma separated list of options in VAR=VAL format.
            -q, --quiet                                          Run the module in quiet mode with no output
      EXPECTED
      expect(subject.usage).to eq(expected_output)
    end
  end
end
