# frozen_string_literal: true

require 'spec_helper'
require 'erb'
require 'open3'
require 'rake'
require 'tmpdir'

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
      end

      it 'preserves apple_ios as its own platform (not collapsed to osx)' do
        expect(described_class.infer_platform('apple_ios/gather/x')).to eq('apple_ios')
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

      it 'infers generic as the single-segment arch for a generic/ payload (maps to ARCH_ALL)' do
        # generic/ single payloads exist and use ARCH_ALL; the fallback must recognize it
        # instead of emitting a nil-arch blocker for a deterministically inferable arch.
        expect(described_class.infer_arch('generic/mypayload', 'payload_single')).to eq('generic')
        expect(described_class.map_arch_const('generic')).to eq('ARCH_ALL')
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

      it 'maps generic to ARCH_ALL, not the nonexistent ARCH_GENERIC' do
        # ARCH_ALL is the real constant (lib/rex/arch.rb); ARCH_GENERIC does not exist,
        # so an ARCH_<UPCASE> rule would emit an unloadable module for the generic/ tree.
        expect(described_class.map_arch_const('generic')).to eq('ARCH_ALL')
      end

      it 'maps archs that the old hand-list omitted (now derived from Rex::Arch::ARCH_TYPES)' do
        # These are valid framework arches (used by real modules) that the previous
        # narrow allow-list rejected -> nil -> unusable scaffold.
        expect(described_class.map_arch_const('zarch')).to eq('ARCH_ZARCH')
        expect(described_class.map_arch_const('ppc64')).to eq('ARCH_PPC64')
        expect(described_class.map_arch_const('dalvik')).to eq('ARCH_DALVIK')
        expect(described_class.map_arch_const('r')).to eq('ARCH_R')
        expect(described_class.map_arch_const('nodejs')).to eq('ARCH_NODEJS')
      end

      it 'covers the complete Rex::Arch::ARCH_TYPES set' do
        # Guard against future drift: every authoritative arch string maps to an
        # existing ARCH_<UPCASE> constant (no nils, no manufactured constants).
        Rex::Arch::ARCH_TYPES.each do |arch|
          const_name = described_class.map_arch_const(arch)
          expect(const_name).not_to be_nil, "#{arch} should be a known arch"
          expect(Rex::Arch.const_defined?(const_name)).to be(true), "#{const_name} should exist"
        end
      end

      it 'returns nil for a nil arch' do
        expect(described_class.map_arch_const(nil)).to be_nil
      end

      it 'returns nil for an unknown arch (routed through the fail-loud nil path, not a manufactured ARCH_* constant)' do
        expect(described_class.map_arch_const('foo')).to be_nil
      end
    end

    describe '.ruby_str' do
      it 'emits a single-quoted literal for an ordinary value (Style/StringLiterals convention)' do
        expect(described_class.ruby_str('Jane Tester')).to eq("'Jane Tester'")
        expect(described_class.ruby_str('linux')).to eq("'linux'")
      end

      it 'escapes (double-quoted) a value containing a single quote, not producing broken Ruby' do
        expect(described_class.ruby_str("O'Connor")).to eq('"O\'Connor"')
      end

      it 'escapes a value containing a backslash' do
        expect(described_class.ruby_str('a\\b')).to eq('"a\\\\b"')
      end

      it 'renders nil as an empty single-quoted literal' do
        expect(described_class.ruby_str(nil)).to eq("''")
      end
    end

    # The rake file can be loaded more than once in one process (this suite loads the
    # module block, then the task-level block loads the whole rakefile). The arch
    # constants are guarded so the second load is a no-op instead of a
    # 'already initialized constant' warning.
    describe 'constant re-definition safety' do
      it 'guards KNOWN_ARCHES and ARCH_CONST_OVERRIDES against re-definition' do
        expect(defined?(MsfModuleGenerator::KNOWN_ARCHES)).to eq('constant')
        expect(defined?(MsfModuleGenerator::ARCH_CONST_OVERRIDES)).to eq('constant')
        # Re-evaluating the module block a second time must not raise (the `unless
        # defined?` guards make the re-assignment a no-op).
        rake_path = Metasploit::Framework.root.join('lib', 'tasks', 'module_generator.rake').to_path
        mod_source = File.read(rake_path)[/^module MsfModuleGenerator$.*?^end$/m]
        expect { Object.class_eval(mod_source, rake_path) }.not_to raise_error
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

    it 'evasion emits [nil] Platform and [nil] Arch when un-inferred' do
      source = render('evasion.rb.erb', type: 'evasion', mod_dir: 'evasion')
      expect(source).to include("'Platform' => [nil],")
      expect(source).to include("'Arch' => [nil],")
      # A scalar nil Platform collapses to an empty PlatformList (loads silently), so it
      # is NOT a fail-loud placeholder -- the template must use [nil], not nil.
      expect(source).not_to include("'Platform' => nil,")
    end

    it 'payload_single emits [nil] Platform and nil Arch when un-inferred' do
      source = render('payload_single.rb.erb', type: 'payload_single', mod_dir: 'payloads/singles')
      expect(source).to include("'Platform' => [nil],")
      expect(source).to include("'Arch' => nil")
      # Scalar nil Platform collapses to an empty PlatformList; use [nil] instead.
      expect(source).not_to include("'Platform' => nil,")
    end

    it 'post emits [nil] Platform when un-inferred (not a loadable [])' do
      # A post module tolerates [] at load, which would let an unresolved platform ship;
      # emit [nil] instead -- PlatformList accepts nil but [nil] is not a usable platform,
      # so it flags as incomplete rather than silently shipping with no platform.
      source = render('post.rb.erb', type: 'post', mod_dir: 'post', platform_meta: nil)
      expect(source).to include("'Platform' => [nil],")
      expect(source).not_to include("'Platform' => [],")
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

    it 'post emits Platform as a quoted array element when inferred (not raw/unescaped)' do
      # Regression guard: map_platform_meta returns a scalar string for post, so the
      # reached template branch must still wrap it as ['<platform>'] via ruby_str.
      source = render('post.rb.erb', type: 'post', mod_dir: 'post', platform_meta: 'windows')
      expect(source).to include("'Platform' => ['windows'],")
    end

    it 'escapes an author containing an apostrophe instead of emitting broken Ruby' do
      # Regression guard for ruby_str: "O'Connor" must become a valid escaped literal,
      # never the syntactically broken 'O'Connor'.
      source = render('exploit.rb.erb', type: 'exploit', mod_dir: 'exploits', author: "O'Connor")
      expect(source).to include('"O\'Connor"')
      expect(source).not_to include("'O'Connor'")
      expect(ruby_syntax_ok?(source).first).to be(true)
    end

    # Notes default to UNKNOWN_* sentinels (which Lint/ModuleEnforceNotes flags) so the
    # author is forced to make an explicit stability/side-effect/reliability decision,
    # rather than a valid-but-unconsidered empty array.
    it 'emits UNKNOWN_* Notes sentinels (forcing placeholders) for Notes-bearing types' do
      {
        'exploit.rb.erb' => { type: 'exploit', mod_dir: 'exploits' },
        'auxiliary.rb.erb' => { type: 'auxiliary', mod_dir: 'auxiliary' },
        'post.rb.erb' => { type: 'post', mod_dir: 'post' }
      }.each do |template, opts|
        source = render(template, **opts)
        expect(source).to include("'Stability' => UNKNOWN_STABILITY"), "#{template} Stability"
        expect(source).to include("'SideEffects' => UNKNOWN_SIDE_EFFECTS"), "#{template} SideEffects"
        expect(source).to include("'Reliability' => UNKNOWN_RELIABILITY"), "#{template} Reliability"
        expect(source).not_to include("'Stability' => []"), "#{template} should not ship empty-array Notes"
      end
    end

    it 'evasion carries no Notes block (evasion does not require Notes; the cop excludes it)' do
      # AGENTS.md module-type table: Evasion Notes = No. Lint/ModuleEnforceNotes is scoped
      # to exploits/auxiliary/post only, so an UNKNOWN_* sentinel here would never be flagged.
      source = render('evasion.rb.erb', type: 'evasion', mod_dir: 'evasion')
      expect(source).not_to include("'Notes'")
      expect(source).not_to include('UNKNOWN_STABILITY')
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

  # cgranleese-r7 review: placeholder comments should carry BOTH the source-file
  # reference (useful to agents, always in sync with the branch) AND a docs-site link
  # (useful to humans, explains what the values mean). Additive, not a replacement.
  describe 'placeholder comments link the docs alongside the source path' do
    it 'exploit Rank TODO links the exploit-ranking docs and keeps the constants.rb path' do
      source = render('exploit.rb.erb', type: 'exploit', mod_dir: 'exploits')
      expect(source).to include('docs.metasploit.com/docs/using-metasploit/intermediate/exploit-ranking.html')
      expect(source).to include('lib/msf/core/constants.rb')
    end

    it 'exploit check comment links the how-to-write-a-check-method docs' do
      source = render('exploit.rb.erb', type: 'exploit', mod_dir: 'exploits')
      expect(source).to include('docs.metasploit.com/docs/development/developing-modules/guides/how-to-write-a-check-method.html')
    end

    %w[exploit auxiliary post].each do |t|
      it "#{t} Notes comment links the metadata-definitions docs and keeps the constants.rb path" do
        source = render("#{t}.rb.erb", type: t, mod_dir: (t == 'exploit' ? 'exploits' : t))
        expect(source).to include('definition-of-module-reliability-side-effects-and-stability.html')
        expect(source).to include('lib/msf/core/constants.rb')
      end
    end
  end

  # AGENTS.md / CONTRIBUTING.md Mixin Ordering: `prepend AutoCheck` must be LAST,
  # after every include, so a contributor uncommenting the include slot keeps the order.
  describe 'AutoCheck prepend ordering' do
    %w[exploit auxiliary].each do |t|
      it "#{t} template places the AutoCheck prepend after the include TODO slot" do
        source = render("#{t}.rb.erb", type: t, mod_dir: (t == 'exploit' ? 'exploits' : 'auxiliary'))
        include_slot = source.index('# include Msf::Exploit::Remote::HttpClient')
        prepend_line = source.index('prepend Msf::Exploit::Remote::AutoCheck')
        expect(include_slot).not_to be_nil
        expect(prepend_line).not_to be_nil
        expect(prepend_line).to be > include_slot
      end
    end

    it 'auxiliary orders protocol slot -> reporting mixin -> AutoCheck (AGENTS.md)' do
      # The protocol include TODO must sit ABOVE the reporting mixin, so uncommenting it
      # yields the required protocol -> reporting -> AutoCheck order.
      source = render('auxiliary.rb.erb', type: 'auxiliary', mod_dir: 'auxiliary')
      protocol_slot = source.index('# include Msf::Exploit::Remote::HttpClient')
      report_line = source.index('include Msf::Auxiliary::Report')
      prepend_line = source.index('prepend Msf::Exploit::Remote::AutoCheck')
      expect(protocol_slot).to be < report_line
      expect(report_line).to be < prepend_line
    end
  end

  # Target Type cannot be inferred from the requested path, so the exploit template
  # must emit a fail-loud placeholder + TODO rather than silently guessing :dropper.
  describe 'exploit target Type is a placeholder, not a guess' do
    it 'emits Type => nil with a TODO and never a hardcoded :dropper guess' do
      source = render('exploit.rb.erb', type: 'exploit', mod_dir: 'exploits')
      expect(source).to include("'Type' => nil")
      expect(source).to match(/TODO.*Type/)
      expect(source).not_to include("'Type' => :dropper")
    end
  end

  # CachedSize = 0 is a valid-but-usually-wrong literal; a stale size is flagged by
  # PayloadCachedSize. The scaffold must default to :dynamic (always correct) with a
  # PLACEHOLDER prompting the real byte size, not a hardcoded 0.
  describe 'payload_single CachedSize is a placeholder, not a hardcoded 0' do
    it 'emits CachedSize = :dynamic with a PLACEHOLDER, never CachedSize = 0' do
      source = render('payload_single.rb.erb', type: 'payload_single', mod_dir: 'payloads/singles')
      expect(source).to include('CachedSize = :dynamic')
      expect(source).to match(/PLACEHOLDER.*\n.*CachedSize|CachedSize.*:dynamic/)
      expect(source).not_to match(/^\s*CachedSize\s*=\s*0\s*$/)
    end
  end

  # DisclosureDate cannot be inferred from the path. It must be a fail-loud placeholder
  # that msftidy's format check rejects, not the (plausible-but-usually-wrong) generation
  # date, which passes tooling silently.
  describe 'exploit DisclosureDate is a fail-loud placeholder, not the generation date' do
    it "emits 'TODO-YYYY-MM-DD' (which msftidy rejects) and not a real YYYY-MM-DD date" do
      source = render('exploit.rb.erb', type: 'exploit', mod_dir: 'exploits', date: '2026-09-16')
      expect(source).to include("'DisclosureDate' => 'TODO-YYYY-MM-DD'")
      expect(source).not_to include("'DisclosureDate' => '2026-09-16'")
    end
  end

  # SessionTypes is a compatibility claim the scaffold cannot verify. Default to an empty
  # list with a TODO forcing an explicit choice, not both meterpreter and shell.
  describe 'post SessionTypes is an explicit choice, not both by default' do
    it 'emits an empty SessionTypes with a TODO, never a hardcoded [meterpreter, shell]' do
      source = render('post.rb.erb', type: 'post', mod_dir: 'post')
      expect(source).to include("'SessionTypes' => []")
      expect(source).to match(/TODO.*[Ss]ession/)
      expect(source).not_to include("'SessionTypes' => ['meterpreter', 'shell']")
    end
  end
end

# Task-level coverage: exercises the public msf:generate workflow (arg/path validation,
# source/doc destination mapping, collision handling, dry-run, and real writes) that the
# helper/render specs above do not reach. Runs in an isolated temp CWD because the task
# writes to CWD-relative modules/ and documentation/ trees.
RSpec.describe 'msf:generate rake task (task-level workflow)' do
  before(:all) do
    # Load the task definitions once. The rake file's MsfModuleGenerator module is
    # already loaded above; loading the file also defines the namespace :msf tasks.
    Rake.application = Rake::Application.new
    rake_file = Metasploit::Framework.root.join('lib', 'tasks', 'module_generator.rake').to_path
    Rake.load_rakefile(rake_file)
  end

  # Invoke the generate task with args in an isolated CWD, capturing stdout.
  # Returns [stdout, tmpdir]; raises SystemExit (from abort) propagate to the caller.
  def run_generate(type, path, platform = nil, arch = nil, env: {})
    tmpdir = Dir.mktmpdir('msfgen')
    out = +''
    old_env = env.to_h { |k, _v| [k, ENV.fetch(k, nil)] }
    env.each { |k, v| ENV[k] = v }
    begin
      Dir.chdir(tmpdir) do
        task = Rake::Task['msf:generate']
        task.reenable
        orig = $stdout
        $stdout = StringIO.new
        begin
          task.invoke(type, path, platform, arch)
          out = $stdout.string
        ensure
          $stdout = orig
        end
      end
    ensure
      old_env.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    end
    [out, tmpdir]
  end

  it 'rejects a path with .. traversal segments' do
    expect { run_generate('exploit', '../../outside/evil', 'linux', 'x64') }
      .to raise_error(SystemExit)
  end

  it 'generates an encoder doc with a msfvenom verification step, not a console `run`' do
    # encoder/nop/payload modules are generated/selected, not driven by `use`+`run`;
    # the doc's verification steps and Scenarios transcript must be type-specific.
    _out, dir = run_generate('encoder', 'x86/etask', nil, 'x86',
                             env: { 'MSF_MOD_AUTHOR' => 'Jane Tester' })
    doc = File.read(File.join(dir, 'documentation', 'modules', 'encoder', 'x86', 'etask.md'))
    expect(doc).to include('msfvenom')
    expect(doc).not_to include('Do: `run`')
    expect(doc).not_to match(/^msf6 .*> run$/)
  ensure
    FileUtils.remove_entry(dir) if dir
  end

  it 'generates an exploit doc that still uses the console `use` + `run` flow' do
    _out, dir = run_generate('exploit', 'linux/http/etask2', 'linux', 'x64',
                             env: { 'MSF_MOD_AUTHOR' => 'Jane Tester' })
    doc = File.read(File.join(dir, 'documentation', 'modules', 'exploit', 'linux', 'http', 'etask2.md'))
    expect(doc).to include('Do: `run`')
    expect(doc).not_to include('msfvenom')
  ensure
    FileUtils.remove_entry(dir) if dir
  end

  it 'rejects an absolute path' do
    expect { run_generate('exploit', '/etc/evil', 'linux', 'x64') }
      .to raise_error(SystemExit)
  end

  it 'rejects an invalid module type' do
    expect { run_generate('notatype', 'linux/http/x', 'linux', 'x64') }
      .to raise_error(SystemExit)
  end

  it 'writes the module and doc to the correct source (plural) and doc (singular) trees' do
    _out, dir = run_generate('exploit', 'linux/http/tasktest', 'linux', 'x64',
                             env: { 'MSF_MOD_AUTHOR' => 'Jane Tester' })
    expect(File).to exist(File.join(dir, 'modules', 'exploits', 'linux', 'http', 'tasktest.rb'))
    expect(File).to exist(File.join(dir, 'documentation', 'modules', 'exploit', 'linux', 'http', 'tasktest.md'))
  ensure
    FileUtils.remove_entry(dir) if dir
  end

  it 'writes a single payload doc to payload/<path>, matching the singles-stripped fullname' do
    # The loader strips singles/ from the reference name, so the runtime fullname is
    # payload/<path> and doc lookup (by fullname) expects the doc there -- NOT under
    # payload/singles/. Only the physical source keeps the singles segment.
    _out, dir = run_generate('payload_single', 'linux/x64/ptask', 'linux', 'x64',
                             env: { 'MSF_MOD_AUTHOR' => 'Jane Tester' })
    expect(File).to exist(File.join(dir, 'modules', 'payloads', 'singles', 'linux', 'x64', 'ptask.rb'))
    expect(File).to exist(File.join(dir, 'documentation', 'modules', 'payload', 'linux', 'x64', 'ptask.md'))
    expect(File).not_to exist(File.join(dir, 'documentation', 'modules', 'payload', 'singles', 'linux', 'x64', 'ptask.md'))
  ensure
    FileUtils.remove_entry(dir) if dir
  end

  it 'aborts when the documentation file already exists (dual-destination collision)' do
    dir = Dir.mktmpdir('msfgen')
    doc = File.join(dir, 'documentation', 'modules', 'exploit', 'linux', 'http', 'collide.md')
    FileUtils.mkdir_p(File.dirname(doc))
    File.write(doc, 'HANDWRITTEN')
    Rake::Task['msf:generate'].reenable
    orig = $stdout
    $stdout = StringIO.new
    begin
      expect { Dir.chdir(dir) { Rake::Task['msf:generate'].invoke('exploit', 'linux/http/collide', 'linux', 'x64') } }
        .to raise_error(SystemExit)
    ensure
      $stdout = orig
    end
    # The pre-existing hand-written doc must be untouched.
    expect(File.read(doc)).to eq('HANDWRITTEN')
  ensure
    FileUtils.remove_entry(dir) if dir
  end

  it 'writes nothing in dry-run mode' do
    _out, dir = run_generate('exploit', 'linux/http/drytest', 'linux', 'x64',
                             env: { 'MSF_DRY_RUN' => '1' })
    expect(Dir.glob(File.join(dir, '**', '*.rb'))).to be_empty
    expect(Dir.glob(File.join(dir, '**', '*.md'))).to be_empty
  ensure
    FileUtils.remove_entry(dir) if dir
  end
end
