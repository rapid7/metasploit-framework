# frozen_string_literal: true

$LOAD_PATH.unshift(File.join(__dir__, '..', '..', '..', '..', 'spec'))
$LOAD_PATH.unshift(File.join(__dir__, '..', '..', '..', '..', 'lib'))

require 'active_support'
require 'active_support/core_ext'
require 'allure_config'
require 'json'
require 'erb'
require 'optparse'
require 'msfenv'
require 'rex'
require 'rex/post'

module ReportGeneration
  class SupportMatrix
    def initialize(data)
      @data = data
    end

    def generation_date
      @generation_date ||= Time.now.strftime('%FT%T')
    end

    def all_commands
      Rex::Post::Meterpreter::CommandMapper.get_command_names
    end

    def table
      sorted_sessions = @data.fetch(:sessions, []).sort_by { |session| session[:session_type] }

      # Group into buckets, and prioritize sort order
      extension_names = [
        # 'Required' Meterpreter extensions
        'core',
        'stdapi',

        'sniffer',
        'extapi',
        'kiwi',
        'python',
        'unhook',
        'appapi',
        'winpmem',
        'powershell',
        'lanattacks',
        'priv',
        'incognito',
        'peinjector',
        'espia',
        'android',

        # any missing new/missing extensions will added to the end lexicographically
      ]

      # Add any new extension names that aren't currently known about
      extension_names += all_commands.each_with_object([]) do |command, unknown_extensions|
        command_prefix = command.split('_').first
        next if extension_names.include?(command_prefix)

        unknown_extensions << command_prefix
      end.sort

      ordered_commands = all_commands.sort_by do |command|
        command_prefix = command.split('_').first
        sort_index = extension_names.index(command_prefix)
        sort_index
      end

      # Map session type to supported commands. i.e. { osx: { command_name_1: true } }
      sessions_to_supported_commands_hash = sorted_sessions.each_with_object({}) do |session, hash|
        session_type = session[:session_type]
        # Map command name to its availability
        supported_command_map = session[:commands].each_with_object({}) do |command, map|
          command_name = command[:name]
          map[command_name] = true
        end
        hash[session_type] = supported_command_map
      end

      columns = [{ heading: '' }] + sorted_sessions.map do |session|
        { heading: session[:session_type], metadata: session[:metadata] }
      end

      rows = extension_names.map do |extension_name|
        extension_commands = ordered_commands.select { |command| command.start_with?(extension_name) }

        command_rows = extension_commands.map do |command|
          session_supported_cells = sessions_to_supported_commands_hash.map do |(_session, compatibility)|
            compatibility.include?(command)
          end

          [command] + session_supported_cells
        end
        extension_coverage = sessions_to_supported_commands_hash.map do |(_session, compatibility)|
          implemented_count = extension_commands.select { |command| compatibility.include?(command) }.size
          total_count = extension_commands.size
          percentage = ((implemented_count.to_f / total_count) * 100).to_i

          "#{percentage}%"
        end

        {
          heading: [extension_name] + extension_coverage,
          values: command_rows
        }
      end

      {
        columns: columns,
        rows: rows
      }
    end

    def get_binding
      binding
    end
  end

  def self.extract_data(options)
    if options[:allure_data]
      results_directory = options[:allure_data]

      test_result_files = Dir['**/*-result.json', base: results_directory]
      meterpreter_compatibility_results = test_result_files.filter_map do |test_result_file|
        path = File.join(results_directory, test_result_file)
        test_result_json = JSON.parse(File.read(path), symbolize_names: true)

        compatibility_attachment = test_result_json.fetch(:attachments, [])
                                       .find { |attachment| attachment[:name] == 'available commands' }
        next unless compatibility_attachment

        compatibility_attachment_path = File.join(File.dirname(path), compatibility_attachment[:source])
        compatibility_json = JSON.parse(File.read(compatibility_attachment_path), symbolize_names: true)
        compatibility_json[:sessions].each do |session|
          session[:metadata] = test_result_json[:parameters].each_with_object({}) do |param, acc|
            acc[param[:name]] = param[:value]
          end
        end

        compatibility_json
      end

      sessions = meterpreter_compatibility_results.flat_map { |results| results[:sessions] }
      sorted_sessions = sessions.sort_by do |session|
        [session[:session_type], session[:metadata]['host_runner_image'], session[:metadata]['meterpreter_runtime_version'].to_s]
      end

      unique_sessions = sorted_sessions.each_with_object({}) do |session, acc|
        acc[session[:session_type]] = session
      end.values

      aggregated_data = {
        sessions: unique_sessions
      }

      aggregated_data
    else
      data_path = options.fetch(:data_path)
      JSON.parse(File.read(data_path), symbolize_names: true)
    end
  end

  def self.generate(options)
    data = extract_data(options)
    support_matrix = SupportMatrix.new(data)

    if options[:format] == :json
      $stdout.write JSON.pretty_generate(support_matrix.data)
    else
      template = File.read(File.join(File.dirname(__FILE__), 'template.erb'))
      renderer = ERB.new(template, trim_mode: '-')

      html = renderer.result(support_matrix.get_binding)
      $stdout.write(html)
    end
  end
end

if $PROGRAM_NAME == __FILE__
  options = {}
  options_parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{File.basename(__FILE__)} [options]"

    opts.on '-h', '--help', 'Help banner.' do
      return print(opts.help)
    end

    opts.on('--allure-data path', 'Use allure as the data source') do |allure_data|
      allure_data ||= AllureRspec.configuration.results_directory
      options[:allure_data] = allure_data
    end

    opts.on('--data-path path',
            'The path to the report generated by scripts/resource/meterpreter_compatibility.rc') do |data_path|
      options[:data_path] = data_path
    end

    opts.on('--format value', %i[json html], 'Render in a given format') do |format|
      options[:format] = format
    end
  end
  options_parser.parse!

  ReportGeneration.generate(options)
end
