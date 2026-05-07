##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Ollama Scanner',
        'Description' => %q{
          This module identifies ollama instances and enumerates the LLM
          models which have been loaded and are running.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die'
        ],
        'References' => [
          ['URL', 'https://ollama.readthedocs.io/en/api/']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(11434),
        OptString.new('TARGETURI', [true, 'Base URI', '/']),
      ]
    )
  end

  def humanize(bytes)
    return '0 B' if bytes <= 0

    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = [(Math.log2(bytes) / 10).to_i, units.length - 1].min
    '%.2f %s' % [bytes.to_f / (1024**i), units[i]]
  end

  def ollama?
    res = send_request_cgi({ 'uri' => normalize_uri(datastore['TARGETURI']) })

    return res.body == 'Ollama is running' if res && res.code == 200

    nil
  end

  def generate
    res = send_request_cgi({ 'uri' => normalize_uri(datastore['TARGETURI'], 'api', 'generate') })

    return res.get_json_document if res && res.code == 200

    nil
  end

  def list_local_models
    res = send_request_cgi({ 'uri' => normalize_uri(datastore['TARGETURI'], 'api', 'tags') })

    return res.get_json_document if res && res.code == 200

    nil
  end

  def list_running_models
    res = send_request_cgi({ 'uri' => normalize_uri(datastore['TARGETURI'], 'api', 'ps') })

    return res.get_json_document if res && res.code == 200

    nil
  end

  def get_model_info(model)
    post_data = {
      'model' => model
    }
    post_json = JSON.generate(post_data)
    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'application/json',
      'data' => post_json,
      'uri' => normalize_uri(target_uri.path, 'api', 'show')
    })

    return res.get_json_document if res && res.code == 200

    nil
  end

  def get_temperature(details)
    unless details.nil? || details['parameters'].nil?
      details['parameters'].each_line do |line|
        next unless line.start_with?('temperature')

        return line.split[1]
      end
    end
    'N/A'
  end

  def get_system_prompt(details)
    unless details.nil? || details['modelfile'].nil?
      details['modelfile'].each_line do |line|
        next unless line.start_with?('SYSTEM ')

        return line.split('SYSTEM ')[1]
      end
    end
    'N/A'
  end

  def run_host(ip)
    vprint_status("Checking #{ip}")
    unless ollama?
      vprint_error('Ollama instance not found')
      return
    end
    models_table = Rex::Text::Table.new(
      'Header' => "#{ip} Ollama Models",
      'Indent' => 2,
      'Columns' => [
        'Name',
        'Release',
        'Status',
        'Size',
        'Parameter Size',
        'Temperature',
        'System Prompt'
      ]
    )
    running = []
    local_models = list_running_models
    local_models['models'].each do |model|
      vprint_status("  Found model: #{model['name']}")
      details = get_model_info(model['name'])
      temperature = get_temperature(details)
      system_prompt = get_system_prompt(details)

      models_table << [
        model['name'].split(':')[0],
        model['name'].split(':')[1],
        'Running',
        humanize(model['size']),
        details.dig('details', 'parameter_size'),
        temperature,
        system_prompt
      ]
      running << model['name']
    end
    local_models = list_local_models
    local_models['models'].each do |model|
      next if running.include?(model['name'])

      vprint_status("  Found model: #{model['name']}")
      details = get_model_info(model['name'])
      temperature = get_temperature(details)
      system_prompt = get_system_prompt(details)

      models_table << [
        model['name'].split(':')[0],
        model['name'].split(':')[1],
        'Installed',
        humanize(model['size']),
        details.dig('details', 'parameter_size'),
        temperature,
        system_prompt
      ]
    end

    print_status(models_table.to_s)
  end
end
