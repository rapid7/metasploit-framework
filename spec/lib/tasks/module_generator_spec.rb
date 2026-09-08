# frozen_string_literal: true

require 'spec_helper'
require 'erb'
require 'open3'

# Load ONLY the `module MsfModuleGenerator ... end` helper block from the rake file
# into the top-level namespace, without invoking Rake. Done at file-load time (not in
# a before hook) so the `describe MsfModuleGenerator` reference below resolves.
rake_path = Metasploit::Framework.root.join('lib', 'tasks', 'module_generator.rake').to_path
mod_source = File.read(rake_path)[/^module MsfModuleGenerator$.*?^end$/m]
raise 'Could not locate MsfModuleGenerator module in rake file' unless mod_source

# Load the helper module into the top-level namespace (trusted repo source, isolated to
# the MsfModuleGenerator module) so the describe reference below resolves at load time.
Object.class_eval(mod_source, rake_path)
# Exercises the msf:generate module generator without invoking Rake: it uses the
# MsfModuleGenerator helper module loaded above and renders each ERB template
# directly. This keeps the suite deterministic and free of framework/DB bootstrapping.
RSpec.describe 'msf:generate module generator' do
  # Render a template the same way the rake task does: ERB with trim_mode '-',
  # against a binding that supplies the template variables. The parameter list mirrors
  # the template variables 1:1 for readability, so the length cop is disabled here.
  def render(template_name, mod_name: 'Test Module', author: 'Tester', cve: nil, # rubocop:disable Metrics/ParameterLists
             date: '2026-01-01', platform: nil, arch_const: nil, platform_meta: nil,
             type: 'exploit', path: 'linux/http/test', mod_dir: 'exploits')
    template_path = File.join(
      Metasploit::Framework.root.join('lib', 'tasks', 'templates').to_path,
      template_name
    )
    ERB.new(File.read(template_path), trim_mode: '-').result(binding)
  end

  def ruby_syntax_ok?(source)
    _out, err, status = Open3.capture3('ruby', '-c', stdin_data: source)
    [status.success?, err]
  end

  describe MsfModuleGenerator do
    describe '.infer_platform' do
      it 'maps windows/win prefixes to win' do
        expect(described_class.infer_platform('windows/http/x')).to eq('win')
        expect(described_class.infer_platform('win/http/x')).to eq('win')
      end

      it 'maps linux, unix, and osx prefixes' do
        expect(described_class.infer_platform('linux/http/x')).to eq('linux')
        expect(described_class.infer_platform('unix/misc/x')).to eq('unix')
        expect(described_class.infer_platform('osx/gather/x')).to eq('osx')
        expect(described_class.infer_platform('apple_ios/gather/x')).to eq('osx')
      end

      it 'returns nil for multi (cannot pick one) and unknown prefixes' do
        expect(described_class.infer_platform('multi/http/x')).to be_nil
        expect(described_class.infer_platform('custom/foo/x')).to be_nil
      end
    end

    describe '.infer_arch' do
      it 'takes the first segment as arch for encoder and nop' do
        expect(described_class.infer_arch('x86/test', 'encoder')).to eq('x86')
        expect(described_class.infer_arch('x64/test', 'nop')).to eq('x64')
      end

      it 'takes a known second segment as arch for payload_single' do
        expect(described_class.infer_arch('linux/x64/test', 'payload_single')).to eq('x64')
      end

      it 'takes a known single-segment arch for payload_single' do
        expect(described_class.infer_arch('cmd/test', 'payload_single')).to eq('cmd')
      end

      it 'returns nil for exploit/auxiliary/evasion (never guesses from platform)' do
        expect(described_class.infer_arch('windows/http/x', 'exploit')).to be_nil
        expect(described_class.infer_arch('scanner/http/x', 'auxiliary')).to be_nil
        expect(described_class.infer_arch('windows/wd/x', 'evasion')).to be_nil
      end
    end

    describe '.map_arch_const' do
      it 'maps known arch strings to framework constants' do
        expect(described_class.map_arch_const('x64')).to eq('ARCH_X64')
        expect(described_class.map_arch_const('cmd')).to eq('ARCH_CMD')
        # An arch only reachable via the old else-branch must still map correctly
        expect(described_class.map_arch_const('ppc')).to eq('ARCH_PPC')
        expect(described_class.map_arch_const('mipsbe')).to eq('ARCH_MIPSBE')
      end

      it 'returns nil for a nil arch' do
        expect(described_class.map_arch_const(nil)).to be_nil
      end

      it 'returns nil for an unknown arch (routed through the fail-loud nil path, not a manufactured ARCH_* constant)' do
        expect(described_class.map_arch_const('foo')).to be_nil
      end
    end
  end

  # Every template must render to syntactically valid Ruby whether or not the
  # platform/arch could be inferred.
  describe 'template rendering produces valid Ruby' do
    {
      'exploit.rb.erb' => { type: 'exploit', mod_dir: 'exploits' },
      'auxiliary.rb.erb' => { type: 'auxiliary', mod_dir: 'auxiliary' },
      'post.rb.erb' => { type: 'post', mod_dir: 'post' },
      'evasion.rb.erb' => { type: 'evasion', mod_dir: 'evasion' },
      'payload_single.rb.erb' => { type: 'payload_single', mod_dir: 'payloads/singles' },
      'encoder.rb.erb' => { type: 'encoder', mod_dir: 'encoders' },
      'nop.rb.erb' => { type: 'nop', mod_dir: 'nops' }
    }.each do |template, opts|
      it "renders #{template} (un-inferred) as valid Ruby" do
        source = render(template, **opts)
        ok, err = ruby_syntax_ok?(source)
        expect(ok).to be(true), "syntax error in #{template}: #{err}"
      end

      it "renders #{template} (inferred platform+arch) as valid Ruby" do
        source = render(template, platform: 'linux', arch_const: 'ARCH_X64',
                                  platform_meta: 'linux', **opts)
        ok, err = ruby_syntax_ok?(source)
        expect(ok).to be(true), "syntax error in #{template}: #{err}"
      end
    end
  end

  # The core design principle: un-inferrable Platform/Arch must be emitted as
  # fail-loud placeholders (nil / [nil]), never plausible-but-wrong guesses or
  # silently-passing empties ([] / '').
  describe 'fail-loud placeholders for un-inferrable fields' do
    it 'exploit emits [nil] Platform and Arch when neither is inferred' do
      source = render('exploit.rb.erb', type: 'exploit', mod_dir: 'exploits')
      expect(source).to include("'Platform' => [nil]")
      expect(source).to include("'Arch' => [nil]")
      expect(source).not_to include("'Platform' => [],")
      expect(source).not_to include("'Arch' => [],")
    end

    it 'evasion emits nil Platform and [nil] Arch when un-inferred' do
      source = render('evasion.rb.erb', type: 'evasion', mod_dir: 'evasion')
      expect(source).to include("'Platform' => nil,")
      expect(source).to include("'Arch' => [nil],")
      expect(source).not_to include("'Platform' => '',")
    end

    it 'payload_single emits nil Platform and nil Arch when un-inferred' do
      source = render('payload_single.rb.erb', type: 'payload_single', mod_dir: 'payloads/singles')
      expect(source).to include("'Platform' => nil,")
      expect(source).to include("'Arch' => nil")
      expect(source).not_to include("'Platform' => '',")
    end

    it 'encoder and nop emit nil Arch when un-inferred' do
      %w[encoder nop].each do |t|
        source = render("#{t}.rb.erb", type: t, mod_dir: "#{t}s")
        expect(source).to include("'Arch' => nil"), "#{t} should emit nil Arch"
      end
    end

    it 'emits real constants (not placeholders) when arch/platform are provided' do
      source = render('exploit.rb.erb', type: 'exploit', mod_dir: 'exploits',
                                        platform: 'linux', arch_const: 'ARCH_X64')
      expect(source).to include("'Platform' => ['linux']")
      expect(source).to include('ARCH_X64')
      expect(source).not_to include('[nil]')
    end

    # Notes default to UNKNOWN_* sentinels (which Lint/ModuleEnforceNotes flags) so the
    # author is forced to make an explicit stability/side-effect/reliability decision,
    # rather than a valid-but-unconsidered empty array.
    it 'emits UNKNOWN_* Notes sentinels (forcing placeholders) for Notes-bearing types' do
      {
        'exploit.rb.erb' => { type: 'exploit', mod_dir: 'exploits' },
        'auxiliary.rb.erb' => { type: 'auxiliary', mod_dir: 'auxiliary' },
        'post.rb.erb' => { type: 'post', mod_dir: 'post' },
        'evasion.rb.erb' => { type: 'evasion', mod_dir: 'evasion' }
      }.each do |template, opts|
        source = render(template, **opts)
        expect(source).to include("'Stability' => UNKNOWN_STABILITY"), "#{template} Stability"
        expect(source).to include("'SideEffects' => UNKNOWN_SIDE_EFFECTS"), "#{template} SideEffects"
        expect(source).to include("'Reliability' => UNKNOWN_RELIABILITY"), "#{template} Reliability"
        expect(source).not_to include("'Stability' => []"), "#{template} should not ship empty-array Notes"
      end
    end
  end

  # Rank is exploit-only: the exploit template must not hardcode a Rank (it emits a
  # TODO so the ModuleMissingRank cop / author sets one), and non-exploit templates
  # must not carry Rank handling at all.
  describe 'Rank handling is scoped to exploits' do
    it 'exploit template emits no Rank assignment, only a TODO' do
      source = render('exploit.rb.erb', type: 'exploit', mod_dir: 'exploits')
      expect(source).not_to match(/^\s*Rank\s*=/)
      expect(source).to match(/TODO.*Rank/)
    end

    it 'encoder template emits no Rank assignment and no Rank TODO' do
      source = render('encoder.rb.erb', type: 'encoder', mod_dir: 'encoders')
      expect(source).not_to match(/^\s*Rank\s*=/)
      expect(source).not_to match(/Rank/)
    end
  end
end
