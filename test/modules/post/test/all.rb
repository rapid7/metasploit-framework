require 'rex'

lib = File.join(Msf::Config.install_root, "test", "lib")
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Test all applicable post modules',
        'Description' => %q{ This module run all applicable post modules against the current session },
        'License' => MSF_LICENSE,
        'Author' => [ 'alanfoster'],
        'Platform' => [ 'linux', 'unix', 'osx', 'windows', 'java' ],
        'SessionTypes' => [ 'meterpreter', 'shell', 'powershell' ]
      )
    )
  end

  def run
    available_modules = select_available_modules
    session_metadata = "#{session.session_type} session #{session.sid}"

    print_status("Applicable modules:")
    print_line(
      matching_modules_table(available_modules, header: "Valid modules for #{session_metadata}", with_results: false)
    )

    module_results = run_modules(available_modules)

    print_status("Modules results:")
    print_line(matching_modules_table(module_results, header: "Results for #{session_metadata}", with_results: true))
  end

  def select_available_modules
    session_platform = Msf::Module::Platform.find_platform(session.platform)
    session_type = session.type

    module_results = []
    framework.modules.post.each do |refname, _clazz|
      next unless refname.start_with?('test/') && refname != self.refname
      mod = framework.modules.create(refname)

      verify_result = {
        is_session_platform: mod.platform.platforms.include?(session_platform),
        is_session_type: mod.session_types.include?(session_type)
      }
      verify_result[:is_valid] = verify_result[:is_session_platform] && verify_result[:is_session_type]
      module_results << { module: mod, **verify_result }
    end
    module_results
  end

  def run_modules(available_modules)
    results = []
    available_modules.each do |available_module|
      next unless available_module[:is_valid]

      print_status("Running #{available_module[:module].refname} against session #{datastore["SESSION"]}")
      print_status("-" * 80)

      module_replicant = nil
      available_module[:module].run_simple(
        'LocalInput' => user_input,
        'LocalOutput' => user_output,
        'Options' => datastore.copy
      ) { |yielded_module_replicant| module_replicant = yielded_module_replicant }

      results << {
        **available_module,
        tests: module_replicant.tests,
        passed: module_replicant.passed,
        failures: module_replicant.failures,
        skipped: module_replicant.skipped,
      }

      print_status("-" * 80)
    end
    results
  end

  def matching_modules_table(module_results, header:, with_results:)
    name_styler = ::Msf::Ui::Console::TablePrint::CustomColorStyler.new
    boolean_styler = ::Msf::Ui::Console::TablePrint::CustomColorStyler.new({ 'Yes' => '%grn', 'No' => '%red' })
    rows = module_results.sort_by { |module_result| module_result[:is_valid] ? 0 : 1 }.map.with_index do |module_result, index|
      next if with_results && !module_result[:is_valid]

      name_styler.merge!({ module_result[:module].refname => module_result[:is_valid] ? '%grn' : '%red' })
      data = [
        index,
        module_result[:module].refname,
        module_result[:is_session_platform] ? 'Yes' : 'No',
        module_result[:is_session_type] ? 'Yes' : 'No',
      ]

      if with_results
        data += [
          module_result[:tests].to_s,
          module_result[:passed].to_s,
          module_result[:failures].to_s,
          module_result[:skipped].to_s,
        ]
      end

      data
    end.compact

    table = Rex::Text::Table.new(
      'Header' => header,
      'Indent' => 1,
      'Columns' => [ '#', 'Name', 'is_session_platform', 'is_session_type' ] + (with_results ? ['total', 'passed', 'failures', 'skipped'] : []),
      'SortIndex' => -1,
      'WordWrap' => false,
      'ColProps' => {
        'Name' => {
          'Stylers' => [name_styler]
        },
        'is_session_platform' => {
          'Stylers' => [boolean_styler]
        },
        'is_session_type' => {
          'Stylers' => [boolean_styler]
        },
        'total' => {
          'Stylers' => []
        },
        'passed' => {
          'Stylers' => [StyleIfGreaterThanZero.new(color: '%grn')]
        },
        'failures' => {
          'Stylers' => [StyleIfGreaterThanZero.new(color: '%red')]
        },
        'skipped' => {
          'Stylers' => [StyleIfGreaterThanZero.new(color: '%yel')]
        }
      },
      'Rows' => rows
    )

    table.to_s
  end

  class StyleIfGreaterThanZero
    def initialize(color:)
      @color = color
    end

    def style(value)
      value.to_i > 0 ? "#{@color}#{value}%clr"  : value
    end
  end
end
