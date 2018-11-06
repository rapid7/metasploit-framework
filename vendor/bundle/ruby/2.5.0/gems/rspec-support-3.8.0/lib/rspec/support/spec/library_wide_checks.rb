require 'rspec/support/spec/shell_out'

module RSpec
  module Support
    module WhitespaceChecks
      # This malformed whitespace detection logic has been borrowed from bundler:
      # https://github.com/bundler/bundler/blob/v1.8.0/spec/quality_spec.rb
      def check_for_tab_characters(filename)
        failing_lines = []
        File.readlines(filename).each_with_index do |line, number|
          failing_lines << number + 1 if line =~ /\t/
        end

        return if failing_lines.empty?
        "#{filename} has tab characters on lines #{failing_lines.join(', ')}"
      end

      def check_for_extra_spaces(filename)
        failing_lines = []
        File.readlines(filename).each_with_index do |line, number|
          next if line =~ /^\s+#.*\s+\n$/
          failing_lines << number + 1 if line =~ /\s+\n$/
        end

        return if failing_lines.empty?
        "#{filename} has spaces on the EOL on lines #{failing_lines.join(', ')}"
      end
    end
  end
end

RSpec.shared_examples_for "library wide checks" do |lib, options|
  consider_a_test_env_file = options.fetch(:consider_a_test_env_file, /MATCHES NOTHING/)
  allowed_loaded_feature_regexps = options.fetch(:allowed_loaded_feature_regexps, [])
  preamble_for_lib = options[:preamble_for_lib]
  preamble_for_spec = "require 'rspec/core'; require 'spec_helper'"
  skip_spec_files = options.fetch(:skip_spec_files, /MATCHES NOTHING/)

  include RSpec::Support::ShellOut
  include RSpec::Support::WhitespaceChecks

  define_method :files_to_require_for do |sub_dir|
    slash         = File::SEPARATOR
    lib_path_re   = /#{slash + lib}[^#{slash}]*#{slash}lib/
    load_path     = $LOAD_PATH.grep(lib_path_re).first
    directory     = load_path.sub(/lib$/, sub_dir)
    files         = Dir["#{directory}/**/*.rb"]
    extract_regex = /#{Regexp.escape(directory) + File::SEPARATOR}(.+)\.rb$/

    # We sort to ensure the files are loaded in a consistent order, regardless
    # of OS. Otherwise, it could load in a different order on Travis than
    # locally, and potentially trigger a "circular require considered harmful"
    # warning or similar.
    files.sort.map { |file| file[extract_regex, 1] }
  end

  def command_from(code_lines)
    code_lines.join("\n")
  end

  def load_all_files(files, preamble, postamble=nil)
    requires = files.map { |f| "require '#{f}'" }
    command  = command_from(Array(preamble) + requires + Array(postamble))

    stdout, stderr, status = with_env 'NO_COVERAGE' => '1' do
      options = %w[ -w ]
      options << "--disable=gem" if RUBY_VERSION.to_f >= 1.9 && RSpec::Support::Ruby.mri?
      run_ruby_with_current_load_path(command, *options)
    end

    [stdout, strip_known_warnings(stderr), status.exitstatus]
  end

  define_method :load_all_lib_files do
    files = all_lib_files - lib_test_env_files
    preamble  = ['orig_loaded_features = $".dup', preamble_for_lib]
    postamble = ['puts(($" - orig_loaded_features).join("\n"))']

    @loaded_feature_lines, stderr, exitstatus = load_all_files(files, preamble, postamble)
    ["", stderr, exitstatus]
  end

  define_method :load_all_spec_files do
    files = files_to_require_for("spec") + lib_test_env_files
    files = files.reject { |f| f =~ skip_spec_files }
    load_all_files(files, preamble_for_spec)
  end

  attr_reader :all_lib_files, :lib_test_env_files,
              :lib_file_results, :spec_file_results

  before(:context) do
    @all_lib_files           = files_to_require_for("lib")
    @lib_test_env_files      = all_lib_files.grep(consider_a_test_env_file)

    @lib_file_results, @spec_file_results = [
      # Load them in parallel so it's faster...
      Thread.new { load_all_lib_files  },
      Thread.new { load_all_spec_files }
    ].map(&:join).map(&:value)
  end

  def have_successful_no_warnings_output
    eq ["", "", 0]
  end

  it "issues no warnings when loaded", :slow do
    expect(lib_file_results).to have_successful_no_warnings_output
  end

  it "issues no warnings when the spec files are loaded", :slow do
    expect(spec_file_results).to have_successful_no_warnings_output
  end

  it 'only loads a known set of stdlibs so gem authors are forced ' \
     'to load libs they use to have passing specs', :slow do
    loaded_features = @loaded_feature_lines.split("\n")
    if RUBY_VERSION == '1.8.7'
      # On 1.8.7, $" returns the relative require path if that was used
      # to require the file. LIB_REGEX will not match the relative version
      # since it has a `/lib` prefix. Here we deal with this by expanding
      # relative files relative to the $LOAD_PATH dir (lib).
      Dir.chdir("lib") { loaded_features.map! { |f| File.expand_path(f) } }
    end

    loaded_features.reject! { |feature| RSpec::CallerFilter::LIB_REGEX =~ feature }
    loaded_features.reject! { |feature| allowed_loaded_feature_regexps.any? { |r| r =~ feature } }

    expect(loaded_features).to eq([])
  end

  RSpec::Matchers.define :be_well_formed do
    match do |actual|
      actual.empty?
    end

    failure_message do |actual|
      actual.join("\n")
    end
  end

  it "has no malformed whitespace", :slow do
    error_messages = []
    `git ls-files -z`.split("\x0").each do |filename|
      error_messages << check_for_tab_characters(filename)
      error_messages << check_for_extra_spaces(filename)
    end
    expect(error_messages.compact).to be_well_formed
  end
end
