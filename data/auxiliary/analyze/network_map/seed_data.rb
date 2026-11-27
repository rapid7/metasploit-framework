# frozen_string_literal: true

# Network graph test data — 10 hosts, depth-3 topology
# Sections: hosts, services, sessions, credentials, traceroutes,
#           SNMP notes (device type, interfaces, LLDP/CDP, MAC table),
#           vulnerabilities (with CVEs), loot, module runs.
#
# Usage:
#   msf6 > irb
#   >> load '/path/to/metasploit-framework/data/auxiliary/analyze/network_map/seed_data.rb'
#
# Network topology:
#
#               MSF (192.168.0.100)
#                       |
#               192.168.0.1 [gateway hop]
#              /          |          \
#      192.168.1.10  192.168.1.20  192.168.1.50
#      (Win10,pwnd)  (Ubuntu,pwnd)  (Cisco IOS)
#                         |
#                    10.10.0.1 [router hop]
#               /      |      |        \
#         10.10.0.10  .20    .30     .100
#        (Deb,pwnd) (WinSrv) (BSD)  (Printer)
#             |
#        172.16.5.1 [router hop]
#         /      |        \
#   172.16.5.10  .20      .30
#   (WinDC,pwnd) (RHEL)  (ESXi)

framework = ObjectSpace.each_object(Msf::Framework).first
raise 'Msf::Framework instance not found — is MSF running?' unless framework

ws = framework.db.workspace
puts "[*] Workspace: #{ws.name}"

# Generate stable, conspicuously fake identities and secrets. Keeping Faker's
# seed local to this fixture makes screenshots reproducible without retaining
# reusable-looking credentials in source.
original_faker_random = Faker::Config.random
Faker::Config.random = Random.new(21_482)
faker_suffix = -> { Faker::Internet.username(specifier: 6..10).gsub(/[^a-z0-9]/i, '_') }
faker_secret = -> { "FAKER_ONLY_#{Faker::Internet.password(min_length: 18, max_length: 24, mix_case: true, special_characters: true)}" }
fake_usernames = %i[
  domain_admin ticket_service desktop_user backup_service database_service
  linux_admin web_service deployment_user database_admin database_default
  network_admin network_operator hypervisor_admin
].to_h { |role| [role, "faker_#{role}_#{faker_suffix.call}"] }
fake_passwords = fake_usernames.to_h { |role, _name| [role, faker_secret.call] }
fake_hashes = {
  domain_admin: "#{Faker::Crypto.md5}:#{Faker::Crypto.md5}",
  ticket_service: "#{Faker::Crypto.md5}:#{Faker::Crypto.md5}",
  desktop_user: "#{Faker::Crypto.md5}:#{Faker::Crypto.md5}"
}
fake_ssh_fingerprints = {
  linux_admin: "FAKER_ONLY_SHA256:#{Faker::Crypto.sha256} #{fake_usernames[:linux_admin]}@web01",
  deployment_user: "FAKER_ONLY_SHA256:#{Faker::Crypto.sha256} #{fake_usernames[:deployment_user]}@jumpbox"
}
fake_kerberos_key = [Faker::Crypto.sha256].pack('H*')
Faker::Config.random = original_faker_random

def find_host(ws, ip)
  ws.hosts.find_by(address: ip)
end

# Produces the same key-padded ": value" content that snmp_enum.rb stores in notes.
def snmp_kv_block(rows, width: 30)
  rows.map do |row|
    row.map { |k, v| "#{k}#{' ' * [0, width - k.length].max}: #{v}" }.join("\n")
  end.join("\n\n") + "\n"
end

# ── HOSTS ────────────────────────────────────────────────────────────────────

[
  # Depth 1 — directly reachable
  { ip: '192.168.1.10', os_name: 'Microsoft Windows', os_flavor: '10', os_family: 'windows', purpose: 'client', name: 'DESKTOP-CORP01', arch: 'x86_64', mac: '00:50:56:AB:11:10' },
  { ip: '192.168.1.20', os_name: 'Ubuntu Linux', os_flavor: '22.04', os_family: 'linux', purpose: 'server', name: 'web01.corp.local', arch: 'x86_64', mac: '00:50:56:AB:11:20' },
  { ip: '192.168.1.50', os_name: 'Cisco IOS', os_flavor: '15.2', os_family: 'cisco', purpose: 'router', name: 'core-sw01', arch: '', mac: '00:1A:2B:3C:11:50' },
  # Depth 2 — through pivot at 192.168.1.20
  { ip: '10.10.0.10', os_name: 'Debian Linux', os_flavor: '11', os_family: 'linux', purpose: 'server', name: 'db01.internal', arch: 'x86_64', mac: '00:50:56:AB:22:10' },
  { ip: '10.10.0.20', os_name: 'Microsoft Windows Server', os_flavor: '2019', os_family: 'windows', purpose: 'server', name: 'SRV-FILES01', arch: 'x86_64', mac: '00:50:56:AB:22:20' },
  { ip: '10.10.0.30', os_name: 'FreeBSD', os_flavor: '13.2', os_family: 'bsd', purpose: 'server', name: 'mail01.internal', arch: 'amd64', mac: '00:50:56:AB:22:30' },
  { ip: '10.10.0.100', os_name: 'HP Embedded', os_flavor: '', os_family: '', purpose: 'printer', name: 'hp-lj-m501dn', arch: '', mac: '00:1C:7E:AA:BB:CC' },
  # Depth 3 — through pivot at 10.10.0.10
  { ip: '172.16.5.10', os_name: 'Microsoft Windows Server', os_flavor: '2022', os_family: 'windows', purpose: 'server', name: 'DC01.corp.local', arch: 'x86_64', mac: '00:50:56:AB:33:10' },
  { ip: '172.16.5.20', os_name: 'Red Hat Enterprise Linux', os_flavor: '8.7', os_family: 'linux', purpose: 'server', name: 'pgdb01.corp.local', arch: 'x86_64', mac: '00:50:56:AB:33:20' },
  { ip: '172.16.5.30', os_name: 'VMware ESXi', os_flavor: '8.0', os_family: 'vmware', purpose: 'server', name: 'esxi01.corp.local', arch: 'x86_64', mac: '00:50:56:AB:33:30' }
].each do |h|
  framework.db.report_host(workspace: ws, host: h[:ip], os_name: h[:os_name],
                           os_flavor: h[:os_flavor], os_family: h[:os_family], purpose: h[:purpose],
                           name: h[:name], arch: h[:arch], mac: h[:mac], state: 'alive')
  puts "[+] Host #{h[:ip]} — #{h[:name]}"
end

# ── SERVICES (5 per host) ────────────────────────────────────────────────────

{
  '192.168.1.10' => [[445, 'tcp', 'smb'], [3389, 'tcp', 'rdp'], [135, 'tcp', 'msrpc'], [139, 'tcp', 'netbios-ssn'], [80, 'tcp', 'http']],
  '192.168.1.20' => [[22, 'tcp', 'ssh'], [80, 'tcp', 'http'], [443, 'tcp', 'https'], [8080, 'tcp', 'http-proxy'], [3306, 'tcp', 'mysql']],
  '192.168.1.50' => [[22, 'tcp', 'ssh'], [23, 'tcp', 'telnet'], [80, 'tcp', 'http'], [443, 'tcp', 'https'], [161, 'udp', 'snmp']],
  '10.10.0.10' => [[22, 'tcp', 'ssh'], [3306, 'tcp', 'mysql'], [8443, 'tcp', 'https-alt'], [5432, 'tcp', 'postgresql'], [2049, 'tcp', 'nfs']],
  '10.10.0.20' => [[445, 'tcp', 'smb'], [3389, 'tcp', 'rdp'], [80, 'tcp', 'http'], [443, 'tcp', 'https'], [1433, 'tcp', 'ms-sql-s']],
  '10.10.0.30' => [[22, 'tcp', 'ssh'], [25, 'tcp', 'smtp'], [110, 'tcp', 'pop3'], [143, 'tcp', 'imap'], [443, 'tcp', 'https']],
  '10.10.0.100' => [[80, 'tcp', 'http'], [443, 'tcp', 'https'], [515, 'tcp', 'printer'], [9100, 'tcp', 'jetdirect'], [161, 'udp', 'snmp']],
  '172.16.5.10' => [[445, 'tcp', 'smb'], [389, 'tcp', 'ldap'], [636, 'tcp', 'ldaps'], [88, 'tcp', 'kerberos'], [3389, 'tcp', 'rdp']],
  '172.16.5.20' => [[5432, 'tcp', 'postgresql'], [22, 'tcp', 'ssh'], [3306, 'tcp', 'mysql'], [6379, 'tcp', 'redis'], [27017, 'tcp', 'mongodb']],
  '172.16.5.30' => [[22, 'tcp', 'ssh'], [80, 'tcp', 'http'], [443, 'tcp', 'https'], [902, 'tcp', 'vmware-auth'], [9443, 'tcp', 'vmware-https']]
}.each do |ip, svcs|
  svcs.each { |port, proto, name| framework.db.report_service(workspace: ws, host: ip, port: port, proto: proto, name: name, state: 'open') }
  puts "[+] Services #{ip}"
end

# ── SESSIONS ─────────────────────────────────────────────────────────────────

sid = 1
[
  ['192.168.1.10', 'exploit/windows/smb/ms17_010_eternalblue', 'payload/windows/x64/meterpreter/reverse_tcp', nil],
  ['192.168.1.20', 'exploit/multi/http/struts2_rest_xstream', 'payload/linux/x64/meterpreter/reverse_tcp', nil],
  ['10.10.0.10', 'exploit/linux/http/apache_log4j_rce', 'payload/linux/x64/meterpreter/reverse_tcp', nil],
  ['10.10.0.20', 'exploit/windows/smb/ms17_010_psexec', 'payload/windows/x64/meterpreter/reverse_tcp', nil],
  # DC: first session closed, second still active
  ['172.16.5.10', 'exploit/windows/smb/psexec', 'payload/windows/x64/meterpreter/reverse_tcp', Time.now - 7200],
  ['172.16.5.10', 'exploit/windows/smb/ms14_068_kerberos_checksum', 'payload/windows/x64/meterpreter/reverse_tcp', nil]
].each do |ip, exploit, payload, closed|
  h = find_host(ws, ip)
  next unless h

  Mdm::Session.create!(host: h, stype: 'meterpreter', via_exploit: exploit,
                       via_payload: payload, opened_at: Time.now - rand(86_400), closed_at: closed, local_id: sid)
  sid += 1
  puts "[+] Session #{ip} — #{exploit.split('/').last}"
rescue StandardError => e
  puts "[-] Session #{ip}: #{e.message}"
end

# ── CREDENTIALS ──────────────────────────────────────────────────────────────
# 16 unique credentials:
#   5 domain accounts shared across Windows boxes (synthetic domain)
#   5 Linux accounts shared across Linux boxes
#   2 SSH key credentials
#   3 standalone accounts (Cisco, ESXi)
#   1 Kerberos AES-256 encryption key (krbtgt — Golden Ticket material)

root_ssh_fingerprint = fake_ssh_fingerprints[:linux_admin]
deployer_ssh_fingerprint = fake_ssh_fingerprints[:deployment_user]

adk = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
ntlm_admin = fake_hashes[:domain_admin]
ntlm_krbtgt = fake_hashes[:ticket_service]

# ip, port, proto, svc, user, private_data, type, realm_val, realm_key, status
# status: :successful = confirmed working; :untried = discovered but not yet tested
successful = Metasploit::Model::Login::Status::SUCCESSFUL
untried = Metasploit::Model::Login::Status::UNTRIED

creds = [
  # ── Domain accounts (5) — same credential core appears on each Windows box ──
  # 1. Administrator (NTLM) — workstation (pwnd), file server hash found, DC (pwnd)
  ['192.168.1.10', 445, 'tcp', 'smb', fake_usernames[:domain_admin], ntlm_admin, :ntlm_hash, 'FAKER.EXAMPLE', adk, successful],
  ['10.10.0.20', 445, 'tcp', 'smb', fake_usernames[:domain_admin], ntlm_admin, :ntlm_hash, 'FAKER.EXAMPLE', adk, untried],
  ['172.16.5.10', 445, 'tcp', 'smb', fake_usernames[:domain_admin], ntlm_admin, :ntlm_hash, 'FAKER.EXAMPLE', adk, successful],
  # 2. krbtgt (NTLM) — DC only, obtained via DCSync
  ['172.16.5.10', 445, 'tcp', 'smb', fake_usernames[:ticket_service], ntlm_krbtgt, :ntlm_hash, 'FAKER.EXAMPLE', adk, successful],
  # 3. jsmith — workstation RDP (successful), file server RDP (password found, not yet tested)
  ['192.168.1.10', 3389, 'tcp', 'rdp', fake_usernames[:desktop_user], fake_passwords[:desktop_user], :password, 'FAKER.EXAMPLE', adk, successful],
  ['10.10.0.20', 3389, 'tcp', 'rdp', fake_usernames[:desktop_user], fake_passwords[:desktop_user], :password, 'FAKER.EXAMPLE', adk, untried],
  # 4. svc-backup — LDAP on DC (successful), SMB on file server (not yet tested)
  ['172.16.5.10', 389, 'tcp', 'ldap', fake_usernames[:backup_service], fake_passwords[:backup_service], :password, 'FAKER.EXAMPLE', adk, successful],
  ['10.10.0.20', 445, 'tcp', 'smb', fake_usernames[:backup_service], fake_passwords[:backup_service], :password, 'FAKER.EXAMPLE', adk, untried],
  # 5. svc-sql — MSSQL and SMB on file server/DC (service account found, not yet tested)
  ['10.10.0.20', 1433, 'tcp', 'mssql', fake_usernames[:database_service], fake_passwords[:database_service], :password, 'FAKER.EXAMPLE', adk, untried],
  ['172.16.5.10', 445, 'tcp', 'smb', fake_usernames[:database_service], fake_passwords[:database_service], :password, 'FAKER.EXAMPLE', adk, untried],

  # ── Linux accounts (5) — same credential core appears on each Linux box ────
  # 6. root — pwnd boxes successful; others found in /etc/shadow, not yet tested
  ['192.168.1.20', 22, 'tcp', 'ssh', fake_usernames[:linux_admin], fake_passwords[:linux_admin], :password, nil, nil, successful],
  ['10.10.0.10', 22, 'tcp', 'ssh', fake_usernames[:linux_admin], fake_passwords[:linux_admin], :password, nil, nil, successful],
  ['172.16.5.20', 22, 'tcp', 'ssh', fake_usernames[:linux_admin], fake_passwords[:linux_admin], :password, nil, nil, untried],
  ['10.10.0.30', 22, 'tcp', 'ssh', fake_usernames[:linux_admin], fake_passwords[:linux_admin], :password, nil, nil, untried],
  # 7. webapp — MySQL on web server (successful), internal DB (not yet tested)
  ['192.168.1.20', 3306, 'tcp', 'mysql', fake_usernames[:web_service], fake_passwords[:web_service], :password, nil, nil, successful],
  ['10.10.0.10', 3306, 'tcp', 'mysql', fake_usernames[:web_service], fake_passwords[:web_service], :password, nil, nil, untried],
  # 8. deployer — SSH on web server (successful), RHEL DB (not yet tested)
  ['192.168.1.20', 22, 'tcp', 'ssh', fake_usernames[:deployment_user], fake_passwords[:deployment_user], :password, nil, nil, successful],
  ['172.16.5.20', 22, 'tcp', 'ssh', fake_usernames[:deployment_user], fake_passwords[:deployment_user], :password, nil, nil, untried],
  # 9. dbadmin — PostgreSQL on internal DB (successful), RHEL (not yet tested)
  ['10.10.0.10', 5432, 'tcp', 'postgresql', fake_usernames[:database_admin], fake_passwords[:database_admin], :password, nil, nil, successful],
  ['172.16.5.20', 5432, 'tcp', 'postgresql', fake_usernames[:database_admin], fake_passwords[:database_admin], :password, nil, nil, untried],
  # 10. postgres — default creds discovered on both PostgreSQL servers, not yet tested
  ['10.10.0.10', 5432, 'tcp', 'postgresql', fake_usernames[:database_default], fake_passwords[:database_default], :password, nil, nil, untried],
  ['172.16.5.20', 5432, 'tcp', 'postgresql', fake_usernames[:database_default], fake_passwords[:database_default], :password, nil, nil, untried],

  # ── SSH key fingerprints (2) ────────────────────────────────────────────────
  # 11. root SSH key — found in authorized_keys, confirmed working on web server
  ['192.168.1.20', 22, 'tcp', 'ssh', fake_usernames[:linux_admin], root_ssh_fingerprint, :password, nil, nil, successful],
  # 12. deployer SSH key — found on web server, not yet tested against RHEL DB
  ['172.16.5.20', 22, 'tcp', 'ssh', fake_usernames[:deployment_user], deployer_ssh_fingerprint, :password, nil, nil, untried],

  # ── Standalone accounts (3) ─────────────────────────────────────────────────
  # 13. Cisco SSH — confirmed working
  ['192.168.1.50', 22, 'tcp', 'ssh', fake_usernames[:network_admin], fake_passwords[:network_admin], :password, nil, nil, successful],
  # 14. Cisco console/telnet — default creds found in docs, not yet tested
  ['192.168.1.50', 23, 'tcp', 'telnet', fake_usernames[:network_operator], fake_passwords[:network_operator], :password, nil, nil, untried],
  # 15. ESXi root — default password found in deployment notes, not yet tested
  ['172.16.5.30', 22, 'tcp', 'ssh', fake_usernames[:hypervisor_admin], fake_passwords[:hypervisor_admin], :password, nil, nil, untried],

  # ── Kerberos key (1) ────────────────────────────────────────────────────────
  # 16. krbtgt AES-256 key — obtained via DCSync; sufficient to forge Golden Tickets
  [
    '172.16.5.10', 88, 'tcp', 'kerberos', fake_usernames[:ticket_service],
    Metasploit::Credential::KrbEncKey.build_data(
      enctype: 18, # aes256-cts-hmac-sha1-96
      key: fake_kerberos_key,
      salt: "FAKER.EXAMPLE#{fake_usernames[:ticket_service]}"
    ),
    :krb_enc_key, 'FAKER.EXAMPLE', adk, successful
  ]
]

creds.each do |credential|
  ip, port, proto, svc, user, pass, type, realm_val, realm_key, status = credential
  opts = {
    workspace_id: ws.id, origin_type: :service, module_fullname: 'auxiliary/analyze/network_map/seed_data',
    address: ip, port: port, service_name: svc, protocol: proto,
    username: user, private_data: pass, private_type: type,
    status: status
  }
  opts[:last_attempted_at] = Time.now unless status == untried
  opts[:realm_value] = realm_val if realm_val
  opts[:realm_key] = realm_key if realm_key
  framework.db.create_credential_and_login(opts)
  puts "[+] Cred #{user}@#{ip}:#{port} (#{type}, #{status})"
rescue StandardError => e
  puts "[-] Cred #{ip}: #{e.message}"
end

# ── TRACEROUTES ──────────────────────────────────────────────────────────────

gw = { 'address' => '192.168.0.1', 'rtt' => '0.51', 'name' => 'gateway.corp.local' }
pivot1 = { 'address' => '192.168.1.20', 'rtt' => '1.23', 'name' => 'web01.corp.local' }
mid_rtr = { 'address' => '10.10.0.1', 'rtt' => '2.11', 'name' => '' }
pivot2 = { 'address' => '10.10.0.10', 'rtt' => '3.55', 'name' => 'db01.internal' }
deep_rtr = { 'address' => '172.16.5.1', 'rtt' => '4.23', 'name' => '' }

{
  '192.168.1.10' => [gw],
  '192.168.1.20' => [gw],
  '192.168.1.50' => [gw],
  '10.10.0.10' => [gw, pivot1, mid_rtr],
  '10.10.0.20' => [gw, pivot1, mid_rtr],
  '10.10.0.30' => [gw, pivot1, mid_rtr],
  '10.10.0.100' => [gw, pivot1, mid_rtr],
  '172.16.5.10' => [gw, pivot1, mid_rtr, pivot2, deep_rtr],
  '172.16.5.20' => [gw, pivot1, mid_rtr, pivot2, deep_rtr],
  '172.16.5.30' => [gw, pivot1, mid_rtr, pivot2, deep_rtr]
}.each do |ip, hops|
  h = find_host(ws, ip)
  next unless h

  framework.db.report_note(workspace: ws, host: h, ntype: 'host.nmap.traceroute',
                           data: { 'hops' => hops }, update: :unique_data)
  puts "[+] Traceroute #{ip} (#{hops.length} hop#{hops.length == 1 ? '' : 's'})"
rescue StandardError => e
  puts "[-] Traceroute #{ip}: #{e.message}"
end

# ── SNMP NOTES ───────────────────────────────────────────────────────────────
# Simulates output from auxiliary/scanner/snmp/snmp_enum against the Cisco switch
# and the HP printer.  The MAC Address Table for core-sw01 maps known host MACs
# to ports — network_graph.rb uses this to derive L2 topology links.

{
  '192.168.1.50' => {
    'Hostname' => 'core-sw01',
    'Description' => 'Cisco IOS Software, Version 15.2(4)E9, RELEASE SOFTWARE (fc3) ' \
                     'Compiled Thu 28-Mar-19 04:26 by prod_rel_team',
    'Contact' => 'netadmin@corp.local',
    'Location' => 'Server Room - Rack 3',
    'Network interfaces' => snmp_kv_block([
      {
        'Interface' => '[ up ] GigabitEthernet0/0', 'Id' => 1, 'Mac Address' => '00:1a:2b:3c:11:00',
        'Type' => 'ethernet-csmacd', 'Speed' => '1000 Mbps', 'MTU' => 1500,
        'In octets' => 45_678_901, 'Out octets' => 34_567_890
      },
      {
        'Interface' => '[ up ] GigabitEthernet0/1', 'Id' => 2, 'Mac Address' => '00:1a:2b:3c:11:01',
        'Type' => 'ethernet-csmacd', 'Speed' => '1000 Mbps', 'MTU' => 1500,
        'In octets' => 12_345_678, 'Out octets' => 9_876_543
      },
      {
        'Interface' => '[ up ] GigabitEthernet0/2', 'Id' => 3, 'Mac Address' => '00:1a:2b:3c:11:02',
        'Type' => 'ethernet-csmacd', 'Speed' => '1000 Mbps', 'MTU' => 1500,
        'In octets' => 23_456_789, 'Out octets' => 18_765_432
      },
      {
        'Interface' => '[ up ] GigabitEthernet0/3', 'Id' => 4, 'Mac Address' => '00:1a:2b:3c:11:03',
        'Type' => 'ethernet-csmacd', 'Speed' => '1000 Mbps', 'MTU' => 1500,
        'In octets' => 67_890_123, 'Out octets' => 56_789_012
      },
      {
        'Interface' => '[ up ] Vlan1', 'Id' => 5, 'Mac Address' => '00:1a:2b:3c:11:04',
        'Type' => 'other', 'Speed' => '1000 Mbps', 'MTU' => 1500,
        'In octets' => 1_234_567, 'Out octets' => 987_654
      }
    ]),
    'LLDP Neighbors' => snmp_kv_block([
      { 'System Name' => 'web01.corp.local', 'Port Description' => 'ens192', 'Port ID' => 'ens192' }
    ]),
    'CDP Neighbors' => snmp_kv_block([
      {
        'Device ID' => 'gw-rtr01.corp.local', 'IP Address' => '192.168.0.1',
        'Port' => 'GigabitEthernet0/0', 'Platform' => 'cisco ISR4431'
      }
    ]),
    # MACs of hosts on the same L2 segment (192.168.1.x) only.
    # 10.10.0.x hosts are routed — their MACs don't appear in this switch's FDB.
    # Gi0/1 → DESKTOP-CORP01 (192.168.1.10)
    # Gi0/2 → web01           (192.168.1.20)
    'MAC Address Table' => snmp_kv_block([
      { 'MAC Address' => '00:50:56:ab:11:10', 'Port' => 'GigabitEthernet0/1', 'Status' => 'learned' },
      { 'MAC Address' => '00:0c:29:ff:ee:dd', 'Port' => 'GigabitEthernet0/1', 'Status' => 'learned' },
      { 'MAC Address' => '00:50:56:ab:11:20', 'Port' => 'GigabitEthernet0/2', 'Status' => 'learned' }
    ])
  },
  '10.10.0.100' => {
    'Hostname' => 'hp-lj-m501dn',
    'Description' => 'HP ETHERNET MULTI-ENVIRONMENT,ROM S.31.14,JETDIRECT,JD189,EEPROM V.33.46,CIDATE 07/03/2018',
    'Contact' => 'helpdesk@corp.local',
    'Location' => '3rd Floor, Print Station',
    'Network interfaces' => snmp_kv_block([
      {
        'Interface' => '[ up ] HP Internal Print Server', 'Id' => 1,
        'Mac Address' => '00:1c:7e:aa:bb:cc', 'Type' => 'ethernet-csmacd',
        'Speed' => '100 Mbps', 'MTU' => 1500, 'In octets' => 234_567, 'Out octets' => 123_456
      }
    ])
  }
}.each do |ip, snmp_data|
  h = find_host(ws, ip)
  unless h
    puts "[-] SNMP: host #{ip} not found, skipping"
    next
  end
  snmp_data.each do |field, content|
    framework.db.report_note(workspace: ws, host: h, ntype: "snmp.#{field}",
                             proto: 'udp', port: 161, sname: 'snmp',
                             data: { content: content }, update: :unique_data)
    puts "[+] SNMP #{ip} snmp.#{field}"
  rescue StandardError => e
    puts "[-] SNMP #{ip}/#{field}: #{e.message}"
  end
end

# ── VULNERABILITIES ───────────────────────────────────────────────────────────

[
  # ── Windows hosts ─────────────────────────────────────────────────────────
  ['192.168.1.10', 445, 'tcp', 'MS17-010 EternalBlue', 'SMBv1 remote code execution', ['CVE-2017-0143', 'CVE-2017-0144', 'MSB-MS17-010']],
  ['192.168.1.10', 3389, 'tcp', 'BlueKeep', 'RDS pre-auth remote code execution', ['CVE-2019-0708']],
  ['192.168.1.10', 445, 'tcp', 'PrintNightmare', 'Windows Print Spooler RCE / LPE', ['CVE-2021-34527', 'CVE-2021-1675']],
  ['10.10.0.20', 445, 'tcp', 'MS17-010 EternalBlue', 'SMBv1 remote code execution', ['CVE-2017-0143', 'CVE-2017-0144']],
  ['10.10.0.20', 445, 'tcp', 'PrintNightmare', 'Windows Print Spooler RCE / LPE', ['CVE-2021-34527']],
  ['10.10.0.20', 1433, 'tcp', 'MSSQL Weak SA Credentials', 'SA account with trivial password', []],
  ['172.16.5.10', 88, 'tcp', 'MS14-068 Kerberos PAC Forgery', 'Privilege escalation via PAC validation', ['CVE-2014-6324', 'MSB-MS14-068']],
  ['172.16.5.10', 445, 'tcp', 'PrintNightmare', 'Windows Print Spooler RCE / LPE', ['CVE-2021-34527', 'CVE-2021-1675']],
  # ── Linux / web ───────────────────────────────────────────────────────────
  ['192.168.1.20', 80, 'tcp', 'Apache Struts2 RCE', 'REST plugin XStream deserialization RCE', ['CVE-2017-9805']],
  ['192.168.1.20', 3306, 'tcp', 'MySQL Weak Credentials', 'Database accepts default credentials', []],
  ['10.10.0.10', 80, 'tcp', 'Log4Shell', 'Log4j2 JNDI injection RCE', ['CVE-2021-44228']],
  ['10.10.0.10', 5432, 'tcp', 'PostgreSQL Weak Credentials', 'Synthetic default credential accepted', []],
  ['172.16.5.20', 5432, 'tcp', 'PostgreSQL COPY RCE', 'Superuser COPY TO/FROM PROGRAM privilege abuse', ['CVE-2019-9193']],
  # ── VMware ────────────────────────────────────────────────────────────────
  ['172.16.5.30', 443, 'tcp', 'VMware vCenter RCE', 'OpenSLP heap overflow pre-auth RCE', ['CVE-2021-21985']],
  # ── SNMP / network devices ────────────────────────────────────────────────
  ['192.168.1.50', 161, 'udp', 'SNMP Default Community String', 'SNMP agent responds to default "public" community', ['CVE-1999-0517', 'CVE-1999-0516']],
  ['192.168.1.50', 161, 'udp', 'Cisco SNMP Trap Source', 'Trap source not restricted; info disclosure possible', ['CVE-2008-0960']],
  ['10.10.0.100', 161, 'udp', 'SNMP Default Community String', 'Printer SNMP agent uses default "public" community', ['CVE-1999-0517']],
  ['10.10.0.100', 9100, 'tcp', 'HP JetDirect Open Admin', 'JetDirect admin accessible without authentication', []]
].each do |ip, port, proto, name, info, refs|
  framework.db.report_vuln(workspace: ws, host: ip, port: port, proto: proto,
                           name: name, info: info, refs: refs)
  puts "[+] Vuln #{ip}:#{port} — #{name}"
rescue StandardError => e
  puts "[-] Vuln #{ip}: #{e.message}"
end

# ── LOOT (3-8 items per compromised host) ────────────────────────────────────

require 'securerandom'

[
  # 192.168.1.10 — Win10 workstation (4 loot items)
  [
    '192.168.1.10', 'windows.hashes', 'SAM Hashes', 'Local account NTLM hashes from DESKTOP-CORP01',
    "#{fake_usernames[:domain_admin]}:500:#{ntlm_admin}:::\n#{fake_usernames[:desktop_user]}:1001:#{fake_hashes[:desktop_user]}:::"
  ],
  [
    '192.168.1.10', 'windows.registry.lsa', 'LSA Secrets', 'LSA secrets extracted via SECRETSDUMP',
    "FAKER_ONLY_SERVICE\n  FAKER_ONLY_SECRET #{fake_passwords[:database_service]}"
  ],
  [
    '192.168.1.10', 'windows.browser.history', 'Chrome History', 'Chrome browser history export',
    "https://corpintranet.corp.local/hr/payroll\nhttps://mail.corp.local/owa"
  ],
  [
    '192.168.1.10', 'exploit.cmdstager.exec', 'Whoami Output', 'Command execution proof: whoami /all',
    'NT AUTHORITY\\SYSTEM'
  ],

  # 192.168.1.20 — Ubuntu web server (5 loot items)
  [
    '192.168.1.20', 'linux.passwd', '/etc/passwd', 'Full /etc/passwd from web01.corp.local',
    "#{fake_usernames[:linux_admin]}:x:1000:1000::/home/faker-admin:/bin/bash\n#{fake_usernames[:web_service]}:x:1001:1001::/srv/faker-web:/usr/sbin/nologin\n#{fake_usernames[:deployment_user]}:x:1002:1002::/home/faker-deploy:/bin/bash"
  ],
  [
    '192.168.1.20', 'linux.shadow', '/etc/shadow', 'Shadowed password hashes from web01.corp.local',
    "#{fake_usernames[:linux_admin]}:FAKER_ONLY_HASH:19000:0:99999:7:::\n#{fake_usernames[:deployment_user]}:FAKER_ONLY_HASH:19000:0:99999:7:::"
  ],
  [
    '192.168.1.20', 'linux.ssh.authorized_keys', 'authorized_keys', 'SSH authorized_keys for root on web01',
    fake_ssh_fingerprints[:deployment_user]
  ],
  [
    '192.168.1.20', 'linux.config.http', 'nginx.conf', 'nginx configuration including upstream backend IPs',
    'upstream backend { server 10.10.0.10:8080; server 10.10.0.20:8080; }'
  ],
  [
    '192.168.1.20', 'linux.database.config', 'db.config.php', 'Web application database credentials in config',
    "define('DB_HOST', '10.10.0.10');\ndefine('DB_USER', '#{fake_usernames[:web_service]}');\ndefine('DB_PASS', '#{fake_passwords[:web_service]}');"
  ],

  # 10.10.0.10 — Debian DB server (6 loot items)
  [
    '10.10.0.10', 'linux.passwd', '/etc/passwd', 'Full /etc/passwd from db01.internal',
    "#{fake_usernames[:linux_admin]}:x:1000:1000::/home/faker-admin:/bin/bash\n#{fake_usernames[:database_default]}:x:1001:1001::/srv/faker-db:/bin/bash\n#{fake_usernames[:database_admin]}:x:1002:1002::/home/faker-dbadmin:/bin/bash"
  ],
  [
    '10.10.0.10', 'linux.shadow', '/etc/shadow', 'Shadowed password hashes from db01.internal',
    "#{fake_usernames[:linux_admin]}:FAKER_ONLY_HASH:19000:0:99999:7:::\n#{fake_usernames[:database_admin]}:FAKER_ONLY_HASH:19000:0:99999:7:::"
  ],
  [
    '10.10.0.10', 'linux.ssh.private_key', 'id_rsa (root)', 'RSA private key for root — reused across internal hosts',
    'FAKER_ONLY_PRIVATE_KEY_PLACEHOLDER'
  ],
  [
    '10.10.0.10', 'mysql.dump', 'mysql_dump.sql', 'MySQL database dump including webapp schema',
    "CREATE DATABASE faker_web;\nUSE faker_web;\nCREATE TABLE users (id INT, username VARCHAR(64), password_hash VARCHAR(128));\nINSERT INTO users VALUES (1,'#{fake_usernames[:web_service]}','FAKER_ONLY_HASH');"
  ],
  [
    '10.10.0.10', 'linux.cron', 'crontab -l (root)', 'Root crontab revealing backup script and credentials',
    "0 2 * * * /opt/backup.sh --user #{fake_usernames[:database_admin]} --pass #{fake_passwords[:database_admin]} --host 172.16.5.20"
  ],
  [
    '10.10.0.10', 'linux.process.environ', '/proc/1/environ', 'Process environment variables including DB secrets',
    "PATH=/usr/local/sbin:/usr/bin\nDB_PASSWORD=#{fake_passwords[:database_admin]}\nDB_HOST=localhost"
  ],

  # 172.16.5.10 — DC01 domain controller (8 loot items)
  [
    '172.16.5.10', 'windows.hashes', 'NTDS.dit Hashes', 'Full domain NTLM hashes via DCSync (secretsdump)',
    "#{fake_usernames[:domain_admin]}:500:#{ntlm_admin}:::\n#{fake_usernames[:ticket_service]}:502:#{ntlm_krbtgt}:::\n#{fake_usernames[:desktop_user]}:1105:#{fake_hashes[:desktop_user]}:::"
  ],
  [
    '172.16.5.10', 'windows.ad.ldap', 'LDAP Dump', 'Full LDAP dump of corp.local — users, groups, OUs',
    "dn: CN=#{fake_usernames[:domain_admin]},CN=Users,DC=faker,DC=example\nobjectClass: user\nsAMAccountName: #{fake_usernames[:domain_admin]}\nmemberOf: CN=Faker Admins,CN=Users,DC=faker,DC=example"
  ],
  [
    '172.16.5.10', 'windows.kerberos.ccache', 'Golden Ticket', 'Kerberos golden ticket (krbtgt AES-256) — valid 10 years',
    "FAKER_ONLY credential cache — #{fake_usernames[:ticket_service]}/FAKER.EXAMPLE forged ticket"
  ],
  [
    '172.16.5.10', 'windows.ad.gpo', 'GPO Dump', 'Group Policy Objects including logon scripts with hardcoded credentials',
    "\\\\faker.example\\SYSVOL\\faker.example\\Policies\\{FAKER-GUID}\\Machine\\Scripts\\Startup\\setup.bat\nnet use Z: \\\\faker-nas\\data /user:FAKER.EXAMPLE\\#{fake_usernames[:backup_service]} #{fake_passwords[:backup_service]}"
  ],
  [
    '172.16.5.10', 'registry.hive', 'SAM Hive', 'Registry SAM hive (offline hash extraction)',
    '(binary SAM hive — seed placeholder)'
  ],
  [
    '172.16.5.10', 'registry.hive', 'SYSTEM Hive', 'Registry SYSTEM hive (boot key for SAM decryption)',
    '(binary SYSTEM hive — seed placeholder)'
  ],
  [
    '172.16.5.10', 'windows.mimikatz', 'Mimikatz Output', 'Mimikatz sekurlsa::logonpasswords output from lsass',
    "msv :\n FAKER_ONLY\n * Username : #{fake_usernames[:domain_admin]}\n * Domain   : FAKER.EXAMPLE\n * NTLM     : #{ntlm_admin}"
  ],
  [
    '172.16.5.10', 'windows.event.log', 'Security Event Log', 'Exported Security event log — logon/logoff events (last 30 days)',
    "EventID 4624 — Successful Logon — #{fake_usernames[:desktop_user]} — FAKER_TIMESTAMP\nEventID 4672 — Special Privileges Assigned — #{fake_usernames[:domain_admin]} — FAKER_TIMESTAMP"
  ]
].each do |ip, ltype, name, info, data|
  h = find_host(ws, ip)
  next unless h

  Mdm::Loot.create!(workspace: ws, host: h, ltype: ltype, name: name, info: info,
                    data: data, path: "/tmp/seed_loot_#{SecureRandom.hex(6)}", content_type: 'text/plain')
  puts "[+] Loot #{ip} — #{name}"
rescue StandardError => e
  puts "[-] Loot #{ip}: #{e.message}"
end

# ── MODULE RUNS ──────────────────────────────────────────────────────────────
# One MetasploitDataModels::ModuleRun per scanner module per host.
# Stagger attempted_at so the history looks realistic.

base_time = Time.now - 7200 # scans started 2 hours ago
run_offset = 0

[
  # 192.168.1.10 — Win10 workstation
  ['192.168.1.10', 'auxiliary/scanner/smb/smb_version', 'succeeded'],
  ['192.168.1.10', 'auxiliary/scanner/smb/smb_ms17_010', 'succeeded'],
  ['192.168.1.10', 'auxiliary/scanner/http/http_version', 'succeeded'],
  # 192.168.1.20 — Ubuntu web server
  ['192.168.1.20', 'auxiliary/scanner/ssh/ssh_version', 'succeeded'],
  ['192.168.1.20', 'auxiliary/scanner/http/http_version', 'succeeded'],
  ['192.168.1.20', 'auxiliary/scanner/ssl/ssl_version', 'succeeded'],
  # 192.168.1.50 — Cisco IOS
  ['192.168.1.50', 'auxiliary/scanner/ssh/ssh_version', 'succeeded'],
  ['192.168.1.50', 'auxiliary/scanner/snmp/snmp_enum', 'succeeded'],
  ['192.168.1.50', 'auxiliary/scanner/http/http_version', 'succeeded'],
  # 10.10.0.10 — Debian DB server
  ['10.10.0.10', 'auxiliary/scanner/ssh/ssh_version', 'succeeded'],
  ['10.10.0.10', 'auxiliary/scanner/ssl/ssl_version', 'succeeded'],
  ['10.10.0.10', 'auxiliary/scanner/mysql/mysql_version', 'succeeded'],
  ['10.10.0.10', 'auxiliary/scanner/postgres/postgres_version', 'succeeded'],
  # 10.10.0.20 — Windows file/SQL server
  ['10.10.0.20', 'auxiliary/scanner/smb/smb_version', 'succeeded'],
  ['10.10.0.20', 'auxiliary/scanner/smb/smb_ms17_010', 'succeeded'],
  ['10.10.0.20', 'auxiliary/scanner/ssl/ssl_version', 'succeeded'],
  ['10.10.0.20', 'auxiliary/scanner/mssql/mssql_ping', 'succeeded'],
  # 10.10.0.30 — FreeBSD mail server
  ['10.10.0.30', 'auxiliary/scanner/ssh/ssh_version', 'succeeded'],
  ['10.10.0.30', 'auxiliary/scanner/smtp/smtp_version', 'succeeded'],
  ['10.10.0.30', 'auxiliary/scanner/ssl/ssl_version', 'succeeded'],
  # 10.10.0.100 — Network printer
  ['10.10.0.100', 'auxiliary/scanner/http/http_version', 'succeeded'],
  ['10.10.0.100', 'auxiliary/scanner/snmp/snmp_enum', 'succeeded'],
  # 172.16.5.10 — DC01
  ['172.16.5.10', 'auxiliary/scanner/smb/smb_version', 'succeeded'],
  ['172.16.5.10', 'auxiliary/scanner/ssl/ssl_version', 'succeeded'],
  # 172.16.5.20 — RHEL DB server
  ['172.16.5.20', 'auxiliary/scanner/ssh/ssh_version', 'succeeded'],
  ['172.16.5.20', 'auxiliary/scanner/postgres/postgres_version', 'succeeded'],
  ['172.16.5.20', 'auxiliary/scanner/mysql/mysql_version', 'succeeded'],
  # 172.16.5.30 — VMware ESXi
  ['172.16.5.30', 'auxiliary/scanner/ssh/ssh_version', 'succeeded'],
  ['172.16.5.30', 'auxiliary/scanner/http/http_version', 'succeeded'],
  ['172.16.5.30', 'auxiliary/scanner/ssl/ssl_version', 'succeeded']
].each do |ip, mod, status|
  h = find_host(ws, ip)
  next unless h

  MetasploitDataModels::ModuleRun.create!(
    module_fullname: mod,
    status: status,
    attempted_at: base_time + (run_offset += 30),
    trackable_type: 'Mdm::Host',
    trackable_id: h.id
  )
  puts "[+] ModuleRun #{ip} — #{mod.split('/').last}"
rescue StandardError => e
  puts "[-] ModuleRun #{ip}/#{mod}: #{e.message}"
end

puts "\n[*] Done. Verify with: hosts / services / creds / vulns / loot"
puts '[*] Generate graph:   use auxiliary/analyze/network_graph && run'
