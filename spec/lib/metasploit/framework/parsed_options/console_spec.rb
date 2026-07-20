require 'spec_helper'
require 'metasploit/framework/parsed_options'

RSpec.describe Metasploit::Framework::ParsedOptions::Console do
  subject(:parsed_options) { described_class.allocate }

  describe '#split_commands' do
    # split_commands is private, so we use send
    let(:result) { parsed_options.send(:split_commands, input) }

    context 'with a single command' do
      let(:input) { 'use exploit/multi/handler' }

      it 'returns the command in an array' do
        expect(result).to eq ['use exploit/multi/handler']
      end
    end

    context 'with multiple semicolon-separated commands' do
      let(:input) { 'use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; run' }

      it 'splits on semicolons' do
        expect(result).to eq [
          'use exploit/multi/handler',
          'set PAYLOAD linux/x64/meterpreter/reverse_tcp',
          'run'
        ]
      end
    end

    context 'with semicolons inside double-quoted strings' do
      let(:input) { 'set POSTDATA "target_host=;!INJECT!&dns-lookup-php-submit-button=Lookup+DNS"; run' }

      it 'does not split on the semicolon within quotes' do
        expect(result).to eq [
          'set POSTDATA "target_host=;!INJECT!&dns-lookup-php-submit-button=Lookup+DNS"',
          'run'
        ]
      end
    end

    context 'with semicolons inside single-quoted strings' do
      let(:input) { "set FOO 'bar;baz'; set QUX quux" }

      it 'does not split on the semicolon within single quotes' do
        expect(result).to eq [
          "set FOO 'bar;baz'",
          'set QUX quux'
        ]
      end
    end

    context 'with multiple quoted segments' do
      let(:input) { 'set A "x;y"; set B "p;q"; run' }

      it 'handles multiple quoted segments correctly' do
        expect(result).to eq [
          'set A "x;y"',
          'set B "p;q"',
          'run'
        ]
      end
    end

    context 'with an empty string' do
      let(:input) { '' }

      it 'returns an empty array' do
        expect(result).to eq []
      end
    end

    context 'with only semicolons and whitespace' do
      let(:input) { ' ; ; ; ' }

      it 'returns an empty array' do
        expect(result).to eq []
      end
    end

    context 'with no semicolons and quotes' do
      let(:input) { 'set FOO "hello world"' }

      it 'returns the whole command' do
        expect(result).to eq ['set FOO "hello world"']
      end
    end

    context 'with the original bug reproduction case' do
      let(:input) { "set VERBOSE true; setg RHOSTS 10.0.0.10; setg LHOST tap0; use exploits/multi/http/os_cmd_exec; set URIPATH /mutillidae/index.php?page=dns-lookup.php; set POSTDATA \"target_host=;!INJECT!&dns-lookup-php-submit-button=Lookup+DNS\";" }

      it 'keeps the POSTDATA value intact' do
        expect(result).to eq [
          "set VERBOSE true",
          "setg RHOSTS 10.0.0.10",
          "setg LHOST tap0",
          "use exploits/multi/http/os_cmd_exec",
          "set URIPATH /mutillidae/index.php?page=dns-lookup.php",
          "set POSTDATA \"target_host=;!INJECT!&dns-lookup-php-submit-button=Lookup+DNS\""
        ]
      end
    end

    context 'with adjacent semicolons' do
      let(:input) { 'cmd1;;cmd2' }

      it 'skips empty entries' do
        expect(result).to eq ['cmd1', 'cmd2']
      end
    end

    context 'with trailing semicolon' do
      let(:input) { 'cmd1; cmd2;' }

      it 'does not produce a trailing empty entry' do
        expect(result).to eq ['cmd1', 'cmd2']
      end
    end

    context 'with escaped quotes inside double-quoted strings' do
      let(:input) { 'set FOO "say \\"hello\\";world"; cmd2' }

      it 'does not treat the escaped quote as a closing quote' do
        expect(result).to eq [
          'set FOO "say \\"hello\\";world"',
          'cmd2'
        ]
      end
    end

    context 'with escaped quotes inside single-quoted strings' do
      let(:input) { "set FOO 'it\\'s;here'; cmd2" }

      it 'does not treat the escaped quote as a closing quote' do
        expect(result).to eq [
          "set FOO 'it\\'s;here'",
          'cmd2'
        ]
      end
    end

    context 'with a backslash outside of quotes' do
      let(:input) { 'set FOO bar\\;baz; cmd2' }

      it 'treats the escaped semicolon as literal' do
        expect(result).to eq [
          'set FOO bar\\;baz',
          'cmd2'
        ]
      end
    end

    context 'with an unclosed quote' do
      let(:input) { 'set FOO "bar;baz' }

      it 'treats the rest of the string as one command' do
        expect(result).to eq ['set FOO "bar;baz']
      end
    end

    # NOTE: Unlike POSIX shell / Ruby's Shellwords, backslash escapes ARE
    # honored inside single-quoted strings. In POSIX, single quotes are
    # fully literal and \' does not work. We intentionally diverge from
    # that behavior because msfconsole is not a POSIX shell and users
    # reasonably expect \' to escape a quote inside single-quoted values.
    context 'when backslash escapes are used inside single quotes (diverges from POSIX/Shellwords)' do
      let(:input) { "set FOO 'don\\'t;stop'; cmd2" }

      it 'honors the backslash escape rather than treating it as literal' do
        expect(result).to eq [
          "set FOO 'don\\'t;stop'",
          'cmd2'
        ]
      end
    end
  end
end
