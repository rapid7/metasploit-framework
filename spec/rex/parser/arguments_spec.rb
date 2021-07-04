require 'rspec'

RSpec.describe Rex::Parser::Arguments do
  let(:subject) do
    Rex::Parser::Arguments.new(
      '-h' => [false, 'Help banner.'],
      '-j' => [false, 'Run in the context of a job.'],
      '-o' => [true, 'A comma separated list of options in VAR=VAL format.'],
      '-q' => [false, 'Run the module in quiet mode with no output']
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
        # Not sure if this flag dropping is intentional behavior
        expected_yields = [
          [nil, 1, 'action_name'],
        ]
        expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
      end

      it 'ignores combined flags that do not exist' do
        input = ['-unknown-flags']
        # Not sure if this flag dropping is intentional behavior
        expected_yields = [
          ['-o', 0, nil],
        ]
        expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
      end
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

      it 'treats long-form flags as arguments' do
        input = ['--foo', '123']
        expected_yields = [
          [nil, 0, '--foo'],
          [nil, 1, '123'],
        ]
        expect { |b| subject.parse(input, &b) }.to yield_successive_args(*expected_yields)
      end
    end
  end
end
