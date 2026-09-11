# frozen_string_literal: true

#
# network_map - a live-updating network topology server for Metasploit.
#
# Companion to the auxiliary/analyze/network_graph module (PR #21482), which
# renders a one-shot snapshot of the workspace as a self-contained HTML file.
# This plugin serves the same visualization from a tiny HTTP server inside
# msfconsole and pushes updates to connected browsers over a websocket as
# hosts, services, sessions, loot, vulns, creds, and module runs land in the
# database - so the graph builds itself while you work.
#
# Usage:
#   load network_map
#   network_map_start [port]           # defaults to 4646 on 127.0.0.1
#   ...run scans / exploits...
#   network_map_stop
#
# The Ruby stdlib has no websocket server and MSF does not ship one, so a
# minimal RFC 6455 implementation (handshake + frame codec) is included below.
# Only text frames are sent to clients; client frames are only used for
# close/ping bookkeeping. No third-party gems are required.
#

require 'socket'
require 'ipaddr'
require 'digest/sha1'
require 'base64'
require 'json'

module Msf
  # Live-updating network topology web server.  Serves the network_graph
  # module's visualization from inside msfconsole and pushes workspace
  # changes to connected browsers over websockets.
  class Plugin::NetworkMapLive < Msf::Plugin

    DEFAULT_PORT = 4646
    DEFAULT_HOST = '127.0.0.1'
    DEFAULT_INTERVAL = 2.0
    MIN_PUSH_SPACING = 0.4 # seconds between broadcasts at most
    CONSOLE_TAIL_MAX = 80  # recent console lines carried on the MSF node

    # Lets the console dispatcher reach the per-framework server instance.
    class << self
      attr_accessor :server
    end

    # Extended onto the console driver so the captured tail carries the same
    # %bld%red[-]%clr style tokens the terminal renders (built by
    # Rex::Ui::Text::Output#print_*; the on_print_proc hook only ever sees
    # the bare message, which is why prefixes and colors went missing).
    # The browser converts the tokens to real colors.  Overriding on the
    # driver (rather than wrapping output) keeps every print path intact -
    # record, then super.
    module ConsoleTapMethods
      def print_error(msg = '')
        @network_map_tap&.call("%bld%red[-]%clr #{msg}")
        super
      end

      alias_method :print_bad, :print_error

      def print_good(msg = '')
        @network_map_tap&.call("%bld%grn[+]%clr #{msg}")
        super
      end

      def print_status(msg = '')
        @network_map_tap&.call("%bld%blu[*]%clr #{msg}")
        super
      end

      def print_warning(msg = '')
        @network_map_tap&.call("%bld%yel[!]%clr #{msg}")
        super
      end

      def print_line(msg = '')
        @network_map_tap&.call(msg.to_s)
        super
      end
    end

    #
    # LiveServer - HTTP + websocket server, DB poller, and graph builder.
    # One instance lives for the plugin's lifetime; start/stop toggle it.
    #
    class LiveServer
      attr_reader :framework, :plugin, :host, :port, :interval, :limits

      WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
      MSF_NODE_ID = '__msf__'

      # Places a local copy of d3 may live, so the page can render offline.
      # The PR's data dir is checked first; the page falls back to the CDN
      # with a 404 here.
      D3_CANDIDATES = [
        File.join(::Msf::Config.data_directory, 'auxiliary', 'analyze', 'network_map', 'd3.v7.9.0.min.js'),
        File.expand_path('../data/auxiliary/analyze/network_map/d3.v7.9.0.min.js', __dir__)
      ].freeze

      def initialize(framework, plugin)
        @framework = framework
        @plugin = plugin
        @running = false
        @clients = []
        @clients_mutex = ::Mutex.new
        @condvar = ::ConditionVariable.new
        @condvar_mutex = ::Mutex.new
        @dirty = false
        @pending = false
        @last_json = nil
        @last_push_mono = 0.0
        @warned = {}
      end

      def running?
        @running
      end

      def url
        "http://#{display_host}:#{@port}/"
      end

      def display_host
        (@host == '0.0.0.0') ? Rex::Socket.source_address : @host
      end

      def loopback?
        ip = begin
          IPAddr.new(@host.to_s)
        rescue StandardError
          nil
        end
        ip&.loopback?
      end

      def client_count
        @clients_mutex.synchronize { @clients.length }
      end

      def start(host: DEFAULT_HOST, port: DEFAULT_PORT, interval: DEFAULT_INTERVAL, limits: {})
        raise 'server already running' if @running

        @host = host || DEFAULT_HOST
        @port = port
        @interval = interval
        @limits = { session: 0, loot: 0, cred: 0 }.merge(limits || {})
        @last_json = nil
        @dirty = true
        @running = true

        @tcp_server = TCPServer.new(@host, @port)
        begin
          @accept_thread = thread_named('network_map:accept') { accept_loop }
          @poll_thread = thread_named('network_map:poll') { poll_loop }
        rescue StandardError
          @running = false
          begin
            @tcp_server.close
          rescue StandardError
            nil
          end
          @tcp_server = nil
          raise
        end
        # Plugin cleanup is not guaranteed to run at console exit, so make
        # sure the sockets close and the threads unwind before the
        # interpreter waits on them.  stop is idempotent.
        at_exit { begin; stop; rescue StandardError; nil; end }
      end

      def stop
        return unless @running || @accept_thread || @poll_thread

        @running = false
        trigger
        begin
          @tcp_server&.close
        rescue StandardError
          nil
        end
        @clients_mutex.synchronize do
          @clients.each do |c|
            c[:sock].close
          rescue StandardError
            nil
          end
          @clients.clear
        end
        [@accept_thread, @poll_thread].each do |t|
          t&.join(2)
        rescue StandardError
          nil
        end
        @accept_thread = nil
        @poll_thread = nil
        @last_json = nil
      end

      # Nudge the poller so framework events (new host, session, module run)
      # show up immediately instead of waiting for the next poll tick.
      def trigger
        @dirty = true
        @condvar_mutex.synchronize do
          @pending = true
          @condvar.signal
        end
      end

      # Console command capture entry point for the event relay.
      def record_console_command(line)
        @plugin.record_console_command(line)
        trigger
      end

      def status
        db_active = false
        ws_name = nil
        counts = {}
        begin
          if @framework.db.active
            db_active = true
            with_db_connection do
              ws = @framework.db.workspace
              ws_name = ws&.name
              counts = {
                hosts: ws.hosts.count,
                services: ws.services.count,
                sessions: ws.sessions.count,
                loot: ws.loots.count,
                vulns: ws.vulns.count
              }
            end
          end
        rescue StandardError
          counts = {}
        end
        {
          running: @running, host: @host, port: @port, interval: @interval,
          clients: client_count, db_active: db_active, workspace: ws_name,
          counts: counts
        }
      end

      private

      def thread_named(name)
        t = ::Thread.new do
          yield
        rescue StandardError => e
          begin
            warn_console("internal error in #{name}: #{e.class}: #{e.message}")
          rescue StandardError
            nil
          end
        end
        t.name = name
        t
      end

      def warn_console(msg)
        @plugin.tap_warning("network_map: #{msg}")
      end

      def warn_once(key, msg)
        return if @warned[key]

        @warned[key] = true
        warn_console(msg)
      end

      def info_console(msg)
        @plugin.tap_status("network_map: #{msg}")
      end

      # ------------------------------------------------------------------
      # Graph construction - ported from auxiliary/analyze/network_graph.rb
      # ------------------------------------------------------------------

      def db_active?
        @framework.db.active
      rescue StandardError
        false
      end

      def with_db_connection(&)
        return yield unless db_active?

        begin
          ::ApplicationRecord.connection_pool.with_connection(&)
        rescue ActiveRecord::ConnectionNotEstablished, ActiveRecord::ConnectionTimeoutError => e
          warn_once("pool:#{e.class}", "database connection pool hiccup: #{e.class}")
          nil
        end
      end

      def build_payload
        meta = {
          generated_at: Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
          clients: client_count
        }
        unless db_active?
          return {
            type: 'update',
            meta: meta.merge(db_active: false, workspace: nil, counts: {}),
            nodes: [msf_node],
            links: []
          }
        end

        ws_data = with_db_connection { collect_workspace_data }
        return nil unless ws_data # pool exhausted; skip this round

        nodes, links = build_graph_data(ws_data)
        {
          type: 'update',
          meta: meta.merge(
            db_active: true,
            workspace: ws_data[:workspace].name,
            limits: @limits,
            counts: {
              hosts: ws_data[:hosts].length,
              sessions: ws_data[:db_sessions].length,
              traceroutes: ws_data[:traceroute_notes].length,
              loot: ws_data[:host_loots].length,
              vulns: ws_data[:host_vulns].length,
              module_events: ws_data[:module_run_events].length,
              module_runs: ws_data[:direct_module_runs].length,
              creds: ws_data[:host_cred_logins].length
            }
          ),
          nodes: nodes,
          links: links
        }
      end

      def collect_workspace_data
        ws = @framework.db.workspace
        hosts = ws.hosts.includes(:services, :sessions).all.to_a
        db_sessions = ws.sessions.all.to_a
        traceroute_notes = ws.notes.where(ntype: 'host.nmap.traceroute').includes(:host).to_a
        host_loots = ws.loots.where.not(host_id: nil).to_a
        host_vulns = ws.vulns.includes(:refs).all.to_a
        module_run_events = ws.events.where(name: 'module_run').all.to_a
        host_ids = hosts.map(&:id)
        direct_module_runs = begin
          MetasploitDataModels::ModuleRun
            .where(trackable_type: 'Mdm::Host', trackable_id: host_ids)
            .all.to_a
        rescue StandardError
          []
        end
        host_cred_logins = begin
          Metasploit::Credential::Login
            .in_workspace_including_hosts_and_services(ws)
            .includes(core: [:realm])
            .all.to_a
        rescue StandardError => e
          warn_once(:cred_query, "credential login query failed: #{e.class}: #{e.message}")
          []
        end
        {
          workspace: ws,
          hosts: hosts,
          db_sessions: db_sessions,
          traceroute_notes: traceroute_notes,
          host_loots: host_loots,
          host_vulns: host_vulns,
          module_run_events: module_run_events,
          direct_module_runs: direct_module_runs,
          host_cred_logins: host_cred_logins
        }
      end

      def msf_node
        lhost = begin
          Rex::Socket.source_address
        rescue StandardError
          '127.0.0.1'
        end
        local_hostname = begin
          Socket.gethostname
        rescue StandardError
          'localhost'
        end
        console = @plugin.console_snapshot
        {
          id: MSF_NODE_ID,
          label: 'Metasploit',
          address: lhost,
          name: local_hostname,
          mac: '',
          os_name: 'Metasploit Framework',
          os_flavor: '',
          os_sp: '',
          os_family: 'msf',
          purpose: 'msf',
          arch: '',
          compromised: false,
          ever_compromised: false,
          session_count: 0,
          sessions: [],
          services: [],
          loots: [],
          device_type: 'msf',
          jobs: jobs_data,
          last_command: console[:last_command],
          console_tail: console[:tail]
        }
      end

      # Background jobs (handlers, servers, ...) for the MSF node sidebar.
      def jobs_data
        @framework.jobs.map do |jid, job|
          {
            id: jid,
            name: job.respond_to?(:name) ? job.name.to_s : job.class.to_s,
            started: begin
              job.start_time ? job.start_time.strftime('%Y-%m-%d %H:%M:%S') : ''
            rescue StandardError
              ''
            end
          }
        end.sort_by { |j| j[:id] }
      rescue StandardError
        []
      end

      def build_graph_data(ws_data)
        hosts = ws_data[:hosts]
        db_sessions = ws_data[:db_sessions]
        traceroute_notes = ws_data[:traceroute_notes]
        host_loots = ws_data[:host_loots]
        host_vulns = ws_data[:host_vulns]
        module_run_events = ws_data[:module_run_events]
        direct_module_runs = ws_data[:direct_module_runs]
        cred_by_host = (ws_data[:host_cred_logins] || []).group_by { |l| l.service.host_id if l.service }

        nodes = []
        links_set = Set.new
        nodes << msf_node

        session_by_host = db_sessions.group_by(&:host_id)
        loot_by_host = host_loots.group_by(&:host_id)
        vuln_by_host = host_vulns.group_by(&:host_id)
        module_run_by_host = direct_module_runs.group_by(&:trackable_id)

        # Build ip -> [module_name] map from module_run events (single-IP RHOST only)
        ipv4_re = /\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/
        event_modules_by_ip = Hash.new { |h, k| h[k] = Set.new }
        module_run_events.each do |ev|
          info = ev.info
          next unless info.is_a?(Hash)

          mod = info[:module_name] || info['module_name']
          next unless mod

          ds = info[:datastore] || info['datastore'] || {}
          rhost = ds['RHOST'] || ds['RHOSTS']
          next unless rhost.to_s =~ ipv4_re

          event_modules_by_ip[rhost.to_s].add(mod)
        end

        subnet_to_pivot = {}
        db_sessions.each do |db_session|
          next unless db_session.respond_to?(:routes)

          db_session.routes.each do |route|
            subnet_to_pivot["#{route.subnet}/#{route.netmask}"] = db_session.host_id
          end
        end

        # Build addr->node_id map for known hosts (used for traceroute link resolution)
        host_id_by_addr = hosts.each_with_object({}) { |h, m| m[h.address.to_s] = "host_#{h.id}" }

        # Parse traceroute notes to build intermediate hop nodes and directed
        # link chains.  Both nmap importers write hops; nmap_document.rb uses
        # "ipaddr", nmap.rb uses "address".
        hop_nodes = {}
        host_rtt = {} # node_id -> rtt (ms) for known hosts seen in traceroute hops
        hosts_with_traceroute = Set.new

        traceroute_notes.each do |note|
          next unless note.data.is_a?(Hash)

          hops = note.data['hops'] || []
          next if hops.empty?

          target_addr = note.host&.address&.to_s
          prev_id = MSF_NODE_ID

          hops.each do |hop|
            ip = (hop['address'] || hop['ipaddr']).to_s.strip
            next if ip.empty? || ip == '*'

            rtt_val = hop['rtt'].to_f
            rtt_val = nil unless rtt_val > 0

            current_id = if host_id_by_addr.key?(ip)
                           nid = host_id_by_addr[ip]
                           host_rtt[nid] ||= rtt_val
                           nid
                         elsif hop_nodes.key?(ip)
                           hop_nodes[ip][:rtt] ||= rtt_val
                           hop_nodes[ip][:id]
                         else
                           node_id = "hop_#{ip.gsub(/[^0-9a-f:]/i, '_')}"
                           hop_nodes[ip] = {
                             id: node_id,
                             label: hop['name'].to_s.empty? ? ip : hop['name'],
                             address: ip,
                             name: hop['name'] || '',
                             mac: '', os_name: '', os_flavor: '', os_sp: '', os_family: '',
                             purpose: '', arch: '',
                             compromised: false, ever_compromised: false,
                             session_count: 0, sessions: [], services: [], loots: [],
                             device_type: 'router',
                             rtt: rtt_val
                           }
                           node_id
                         end

            links_set.add([prev_id, current_id])
            prev_id = current_id
          end

          hosts_with_traceroute.add(target_addr) if target_addr

          # Ensure last hop connects to the known target host node when they differ
          if target_addr && host_id_by_addr.key?(target_addr)
            target_id = host_id_by_addr[target_addr]
            links_set.add([prev_id, target_id]) unless prev_id == target_id
          end
        end

        if subnet_to_pivot.empty? && traceroute_notes.empty?
          warn_once(:no_topology, 'no session routes or traceroute data found - all hosts will hang directly off the MSF node. Run nmap with --traceroute or "route add" behind a pivot session for real topology.')
        end

        hosts.each do |host|
          host_sessions = session_by_host[host.id] || []
          active_sessions = host_sessions.select { |s| s.closed_at.nil? }

          session_limit = @limits[:session].to_i
          display_sessions = session_limit > 0 ? host_sessions.sort_by { |s| s.opened_at || Time.at(0) }.last(session_limit) : host_sessions

          session_data = display_sessions.map do |s|
            ds = s.datastore.is_a?(Hash) ? s.datastore : {}
            {
              id: s.id,
              type: s.stype || 'unknown',
              via_exploit: s.via_exploit || '',
              via_payload: s.via_payload || '',
              lhost: ds['LHOST'] || '',
              lport: ds['LPORT'] || '',
              rport: ds['RPORT'] || '',
              opened_at: s.opened_at&.strftime('%Y-%m-%d %H:%M:%S') || '',
              closed_at: s.closed_at&.strftime('%Y-%m-%d %H:%M:%S') || '',
              active: s.closed_at.nil?
            }
          end

          service_data = host.services
                             .sort_by(&:port)
                             .map { |svc| { port: svc.port, proto: svc.proto, name: svc.name || '', state: svc.state || '' } }

          loot_limit = @limits[:loot].to_i
          display_loots = loot_by_host[host.id] || []
          display_loots = display_loots.last(loot_limit) if loot_limit > 0

          loot_data = display_loots.map do |l|
            {
              ltype: l.ltype || '',
              name: l.name || '',
              info: l.info || '',
              path: l.path || ''
            }
          end

          vuln_data = (vuln_by_host[host.id] || []).map do |v|
            {
              name: v.name || '',
              info: v.info || '',
              refs: v.refs.map(&:name),
              exploited_at: v.exploited_at&.strftime('%Y-%m-%d %H:%M:%S') || ''
            }
          end

          host_module_runs = (module_run_by_host[host.id] || []).map do |mr|
            {
              module_fullname: mr.module_fullname || '',
              status: mr.status || '',
              attempted_at: mr.attempted_at&.strftime('%Y-%m-%d %H:%M:%S') || ''
            }
          end

          cred_limit = @limits[:cred].to_i
          display_creds = (cred_by_host[host.id] || []).uniq(&:core_id)
          display_creds = display_creds.last(cred_limit) if cred_limit > 0

          cred_data = display_creds.map do |login|
            core = login.core
            {
              type: core.private&.type&.split('::')&.last || 'Unknown',
              username: core.public&.username || '',
              domain: core.realm&.value || '',
              status: login.status || ''
            }
          end

          nodes << {
            id: "host_#{host.id}",
            label: (host.name || host.address.to_s),
            address: host.address.to_s,
            name: host.name || '',
            mac: host.mac || '',
            os_name: host.os_name || '',
            os_flavor: host.os_flavor || '',
            os_sp: host.os_sp || '',
            os_family: host.os_family || '',
            purpose: host.purpose || '',
            arch: host.arch || '',
            compromised: active_sessions.any?,
            ever_compromised: host_sessions.any?,
            session_count: active_sessions.count,
            sessions: session_data,
            services: service_data,
            loots: loot_data,
            vulns: vuln_data,
            event_modules: event_modules_by_ip[host.address.to_s].to_a.sort,
            module_runs: host_module_runs,
            creds: cred_data,
            device_type: infer_device_type(host),
            rtt: host_rtt["host_#{host.id}"]
          }

          # Traceroute takes precedence; only add a default link if no
          # traceroute covers this host
          next if hosts_with_traceroute.include?(host.address.to_s)

          pivot_host_id = find_pivot_for_host(host, subnet_to_pivot)
          source_id = pivot_host_id ? "host_#{pivot_host_id}" : MSF_NODE_ID
          links_set.add([source_id, "host_#{host.id}"])
        end

        nodes.concat(hop_nodes.values)
        links = links_set.map { |s, t| { source: s, target: t } }

        [nodes, links]
      end

      def infer_device_type(host)
        purpose = host.purpose.to_s.downcase
        return 'router' if purpose.match?(/router/)
        return 'switch' if purpose.match?(/switch/)
        return 'firewall' if purpose.match?(/firewall/)
        return 'printer' if purpose.match?(/print/)
        return 'phone' if purpose.match?(/phone|mobile/)
        return 'server' if purpose.match?(/server/)
        return 'computer' if purpose.match?(/client|workstation/)

        ports = host.services.map(&:port)
        return 'server' if (ports & [80, 443, 8080, 8443, 3306, 5432, 1433]).any?
        return 'router' if (ports & [179, 520, 521]).any?

        'computer'
      end

      def find_pivot_for_host(host, subnet_to_pivot)
        ip = IPAddr.new(host.address.to_s)
        subnet_to_pivot.each do |cidr, pivot_host_id|
          subnet_ip, netmask = cidr.split('/')
          net = IPAddr.new("#{subnet_ip}/#{netmask}")
          return pivot_host_id if net.include?(ip)
        rescue ArgumentError
          next
        end
        nil
      rescue ArgumentError
        nil
      end

      # Recursively re-encodes all strings in a nested Hash/Array as valid
      # UTF-8.  DB strings (SSH keys, binary fields) often come back tagged
      # ASCII-8BIT; force_encoding reinterprets the bytes as UTF-8, scrub
      # drops any invalid sequences.
      def utf8_sanitize(obj)
        case obj
        when Hash then obj.transform_values { |v| utf8_sanitize(v) }
        when Array then obj.map { |v| utf8_sanitize(v) }
        when String
          return obj if obj.encoding == ::Encoding::UTF_8 && obj.valid_encoding?

          obj.dup.force_encoding('UTF-8').scrub('?')
        else obj
        end
      end

      # ------------------------------------------------------------------
      # Poller - fingerprint the workspace, push snapshots when it changes
      # ------------------------------------------------------------------

      def poll_loop
        last_sig = nil
        while @running
          sig = begin
            with_db_connection { fingerprint } || 'no-db'
          rescue StandardError => e
            "err:#{e.class}"
          end
          if sig != last_sig || @dirty
            @dirty = false
            # Events (on_db_host, on_session_open, on_module_run, ...) arrive
            # in bursts; spacing pushes out avoids rebuild storms.
            spacing = MIN_PUSH_SPACING - (::Process.clock_gettime(::Process::CLOCK_MONOTONIC) - @last_push_mono)
            sleep(spacing) if spacing > 0 && @running
            next unless @running

            payload = begin
              build_payload
            rescue StandardError => e
              warn_once("build:#{e.class}", "graph build failed: #{e.class}: #{e.message}")
              nil
            end
            if payload
              json = ::JSON.generate(utf8_sanitize(payload))
              @last_json = json
              broadcast(json)
              # NOTE: do not narrate pushes here - the console tap records
              # this plugin's own output, so a per-push print line would bump
              # the console-activity counter, change the fingerprint, and
              # push again: an endless print loop while a browser watches.
              @last_push_mono = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
            end
            last_sig = sig
          end
          # Sleep out the interval, but wake early when an event triggers.
          @condvar_mutex.synchronize do
            @pending = false
            @condvar.wait(@condvar_mutex, @interval) unless @pending
          end
        end
      end

      # Cheap aggregate queries that change whenever anything the graph shows
      # changes.  Full rebuild only happens when this signature moves.
      def fingerprint
        # jobs + console activity change the MSF node even without a database
        live_sig = "jobs:#{begin
          @framework.jobs.size
        rescue StandardError
          '?'
        end}|console:#{@plugin.console_activity_version}"
        return "no-db|#{live_sig}" unless db_active?

        ws = @framework.db.workspace
        parts = ["ws:#{ws.id}:#{ws.name}"]
        agg = lambda do |label, rel|
          "#{label}:#{rel.count}:#{rel.maximum(:updated_at).to_i}"
        rescue StandardError
          begin
            "#{label}:#{rel.count}"
          rescue StandardError
            "#{label}:?"
          end
        end
        parts << agg.call('hosts', ws.hosts)
        parts << agg.call('svcs', ws.services)
        parts << agg.call('loot', ws.loots)
        parts << agg.call('vulns', ws.vulns)
        parts << agg.call('events', ws.events)
        parts << agg.call('notes-tr', ws.notes.where(ntype: 'host.nmap.traceroute'))
        begin
          parts << "sess:#{ws.sessions.count}:#{ws.sessions.maximum(:opened_at).to_i}:#{ws.sessions.maximum(:closed_at).to_i}"
        rescue StandardError
          parts << 'sess:?'
        end
        begin
          parts << "mruns:#{MetasploitDataModels::ModuleRun.count}:#{MetasploitDataModels::ModuleRun.maximum(:updated_at).to_i}"
        rescue StandardError
          parts << 'mruns:?'
        end
        begin
          parts << "logins:#{Metasploit::Credential::Login.in_workspace_including_hosts_and_services(ws).count}"
        rescue StandardError
          parts << 'logins:?'
        end
        parts.push(live_sig)
        parts.join('|')
      end

      # ------------------------------------------------------------------
      # HTTP + websocket server
      # ------------------------------------------------------------------

      def accept_loop
        while @running
          begin
            sock = @tcp_server.accept
          rescue IOError, Errno::EBADF
            break # server closed underneath us (stop)
          rescue StandardError => e
            warn_console("accept failed: #{e.class}: #{e.message}")
            break unless @running

            sleep 0.2
            next
          end
          ::Thread.new do
            handle_conn(sock)
          ensure
            begin
              sock.close
            rescue StandardError
              nil
            end
          end
        end
      end

      def handle_conn(sock)
        begin
          sock.setsockopt(::Socket::IPPROTO_TCP, ::Socket::TCP_NODELAY, 1)
        rescue StandardError
          nil
        end
        req_line = sock.gets("\r\n")
        return unless req_line

        method, target, = req_line.split(' ')
        headers = {}
        while (line = sock.gets("\r\n"))
          break if line == "\r\n" || line == "\n"

          k, v = line.split(':', 2)
          headers[k.to_s.strip.downcase] = v.to_s.strip if v
        end
        path = target.to_s.split('?').first

        if path == '/ws' && headers['upgrade'].to_s.downcase == 'websocket'
          ws_client_loop(sock, headers)
          return
        end

        case path
        when '/', '/index.html'
          body = INDEX_HTML
          if method == 'HEAD'
            write_http(sock, 200, 'OK', 'text/html; charset=utf-8', body, head_only: true)
          else
            write_http(sock, 200, 'OK', 'text/html; charset=utf-8', body)
          end
        when '/d3.js'
          d3_path = D3_CANDIDATES.find { |p| p && File.file?(p) }
          if d3_path
            write_http(sock, 200, 'OK', 'application/javascript; charset=utf-8', File.binread(d3_path))
          else
            # The client falls back to the CDN when this 404s.
            write_http(sock, 404, 'Not Found', 'text/plain', "no local d3.js (using CDN)\n")
          end
        when '/graph.json'
          json = @last_json || begin
            payload = build_payload
            payload ? ::JSON.generate(utf8_sanitize(payload)) : '{}'
          end
          write_http(sock, 200, 'OK', 'application/json; charset=utf-8', json)
        when '/health'
          write_http(sock, 200, 'OK', 'text/plain', "ok\n")
        else
          write_http(sock, 404, 'Not Found', 'text/plain', "not found\n")
        end
      rescue IOError, Errno::ECONNRESET, Errno::EPIPE, Errno::ETIMEDOUT
        nil # client hung up mid-request; normal
      rescue StandardError => e
        warn_console("request handling error: #{e.class}: #{e.message}")
      end

      def write_http(sock, code, reason, ctype, body, head_only: false)
        head = +"HTTP/1.1 #{code} #{reason}\r\n" \
               "Content-Type: #{ctype}\r\n" \
               "Content-Length: #{body.bytesize}\r\n" \
               "Connection: close\r\n" \
               "Cache-Control: no-store\r\n" \
               "\r\n"
        sock.write(head)
        sock.write(body) unless head_only
      end

      # --- RFC 6455 websocket --------------------------------------------

      def ws_client_loop(sock, headers)
        key = headers['sec-websocket-key']
        return unless key

        accept = ::Base64.strict_encode64(::Digest::SHA1.digest(key + WS_GUID))
        sock.write(
          "HTTP/1.1 101 Switching Protocols\r\n" \
          "Upgrade: websocket\r\n" \
          "Connection: Upgrade\r\n" \
          "Sec-WebSocket-Accept: #{accept}\r\n" \
          "\r\n"
        )

        client = { sock: sock, write_lock: ::Mutex.new }
        @clients_mutex.synchronize { @clients << client }
        info_console("browser connected (#{client_count} watching)")

        # Push the current snapshot immediately so the first paint can come
        # straight off the socket if the initial /graph.json fetch raced.
        begin
          json = @last_json || begin
            payload = build_payload
            payload ? ::JSON.generate(utf8_sanitize(payload)) : nil
          end
          ws_send_frame(client, json) if json
        rescue StandardError => e
          warn_console("initial snapshot failed: #{e.class}: #{e.message}")
        end

        loop do
          break unless @running

          frame = ws_read_frame(sock)
          break if frame.nil? # EOF / dead socket

          case frame[:opcode]
          when 0x8 # close
            ws_send_frame(client, frame[:payload][0, 2] || '', 0x8)
            break
          when 0x9 # ping
            ws_send_frame(client, frame[:payload], 0xA)
          when 0x1, 0x2 # text/binary from client; nothing to act on
            next
          end
        end
      rescue IOError, Errno::ECONNRESET, Errno::EPIPE, Errno::ETIMEDOUT
        nil # normal disconnect
      rescue StandardError => e
        warn_console("websocket client error: #{e.class}: #{e.message}")
      ensure
        @clients_mutex.synchronize { @clients.delete(client) }
        begin
          sock.close
        rescue StandardError
          nil
        end
        info_console("browser disconnected (#{client_count} watching)") if @running
      end

      # Sends one masked-free (server-to-client) text frame.
      def ws_send_frame(client, data, opcode = 0x1)
        bytes = data.bytesize
        header = [0x80 | opcode] # FIN + opcode
        if bytes < 126
          header << bytes
        elsif bytes < 65_536
          header << 126
          header.concat([bytes].pack('n').bytes)
        else
          header << 127
          header.concat([bytes].pack('Q>').bytes)
        end
        # frame writes must not interleave with pong/close writes from the
        # reader thread on the same socket
        client[:write_lock].synchronize do
          client[:sock].write(header.pack('C*'))
          client[:sock].write(data)
        end
      end

      # Reads a single frame.  Returns nil on EOF.  Client frames are always
      # masked; control frames may interleave with fragmented messages, which
      # we do not need to reassemble (clients only send close/ping here).
      def ws_read_frame(sock)
        b = read_exact(sock, 2)
        return nil unless b

        h0, h1 = b.unpack('C2')
        opcode = h0 & 0x0f
        masked = (h1 & 0x80) != 0
        len = h1 & 0x7f
        if len == 126
          ext = read_exact(sock, 2)
          return nil unless ext

          len = ext.unpack1('n')
        elsif len == 127
          ext = read_exact(sock, 8)
          return nil unless ext

          len = ext.unpack1('Q>')
        end
        mask = masked ? read_exact(sock, 4)&.unpack('C4') : nil
        payload = len.positive? ? read_exact(sock, len) : +''.b
        return nil if payload.nil?

        if mask
          payload = payload.bytes.each_with_index.map { |byte, i| byte ^ mask[i % 4] }.pack('C*')
        end
        { opcode: opcode, payload: payload }
      end

      def read_exact(sock, n)
        data = sock.read(n)
        return nil if data.nil? || data.bytesize != n

        data
      rescue IOError, Errno::ECONNRESET # client vanished mid-frame
        nil
      end

      def broadcast(json)
        dead = []
        @clients_mutex.synchronize { @clients.dup }.each do |client|
          ws_send_frame(client, json)
        rescue StandardError
          dead << client
        end
        return if dead.empty?

        warn_console("dropped #{dead.length} unresponsive websocket client(s)")
        @clients_mutex.synchronize do
          dead.each do |client|
            @clients.delete(client)
            begin
              client[:sock].close
            rescue StandardError
              nil
            end
          end
        end
      end
    end

    #
    # EventRelay - subscribes to framework/db/session events and nudges the
    # poller so fresh data is pushed within ~0.5s instead of the full poll
    # interval.  The poller remains the safety net for anything that does
    # not fire an event (loot, notes, module_run DB events, ...).
    #
    class EventRelay
      include Msf::DatabaseEvent
      include Msf::SessionEvent

      def initialize(server)
        @server = server
      end

      def on_db_client(_client)
        @server&.trigger
      end

      def on_db_host(_host)
        @server&.trigger
      end

      def on_db_host_state(_host, _ostate)
        @server&.trigger
      end

      def on_db_service(_service)
        @server&.trigger
      end

      def on_db_service_state(_host, _port, _ostate)
        @server&.trigger
      end

      def on_db_vuln(_vuln)
        @server&.trigger
      end

      def on_session_open(_session)
        @server&.trigger
      end

      def on_session_close(_session, _reason = '')
        @server&.trigger
      end

      # Console commands, relayed by the driver's standard on_command_proc
      # through framework.events - immune to the hook clobbering every
      # dispatcher instantiation does.
      def on_ui_command(command)
        @server&.record_console_command(command)
      end

      def on_module_run(_mod)
        @server&.trigger
      end

      def on_module_complete(_mod)
        @server&.trigger
      end

      # EventDispatcher#on_module_load calls general subscribers directly,
      # without the respond_to? guard its method_missing path uses, so every
      # general subscriber must implement this even to ignore it.  Without
      # this no-op, any lazy module load ("use <uncached module>") raises
      # NoMethodError and breaks the use command.
      def on_module_load(_name, _mod)
      end
    end

    #
    # Console commands
    #
    class CommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      DEFAULT_LIMITS = { session: 0, loot: 0, cred: 0 }.freeze

      @@start_opts = Rex::Parser::Arguments.new(
        ['-h', '--help'] => [false, 'Help banner'],
        ['--host'] => [true, 'Interface to bind (default 127.0.0.1; 0.0.0.0 exposes your engagement data to the network)'],
        ['--interval'] => [true, 'Database poll interval in seconds (default 2.0)'],
        ['--limit-session'] => [true, 'Max sessions included per host (0 = unlimited, default 0)'],
        ['--limit-loot'] => [true, 'Max loot items included per host (0 = unlimited, default 0)'],
        ['--limit-cred'] => [true, 'Max credentials included per host (0 = unlimited, default 0)']
      )

      def name
        'network_map'
      end

      def commands
        {
          'network_map_start' => 'Start the live network graph web server (usage: network_map_start [port])',
          'network_map_stop' => 'Stop the live network graph web server',
          'network_map_status' => 'Show live network map server status'
        }
      end

      def server
        Plugin::NetworkMapLive.server
      end

      def cmd_network_map_start_help
        print_line 'Usage: network_map_start [port] [options]'
        print_line
        print_line 'Starts a local web server serving a live-updating network graph of the'
        print_line 'current workspace (same visualization as auxiliary/analyze/network_graph).'
        print_line 'Open the printed URL in a browser; it updates over a websocket as hosts,'
        print_line 'services, sessions, loot, vulns, creds and module runs hit the database.'
        print_line
        print_line @@start_opts.usage
      end

      def cmd_network_map_start(*args)
        host = Plugin::NetworkMapLive::DEFAULT_HOST
        port = Plugin::NetworkMapLive::DEFAULT_PORT
        interval = Plugin::NetworkMapLive::DEFAULT_INTERVAL
        limits = DEFAULT_LIMITS.dup

        @@start_opts.parse(args) do |opt, _idx, val|
          case opt
          when '-h', '--help'
            return cmd_network_map_start_help
          when '--host'
            host = val
          when '--interval'
            interval = begin
              Float(val)
            rescue ArgumentError
              print_error("Invalid interval: #{val}")
              return
            end
          when '--limit-session'
            limits[:session] = val.to_i
          when '--limit-loot'
            limits[:loot] = val.to_i
          when '--limit-cred'
            limits[:cred] = val.to_i
          end
        end

        port_arg = args.find { |a| a =~ /\A\d+\z/ }
        if port_arg
          port = port_arg.to_i
        end
        unless port.between?(1, 65_535)
          print_error("Invalid port: #{port}")
          return
        end
        if interval <= 0
          print_error("Invalid interval: #{interval}")
          return
        end

        svr = server
        if svr.nil?
          print_error('network_map plugin is not fully loaded')
          return
        end
        if svr.running?
          print_error("Already running at http://#{svr.host}:#{svr.port}/ - run network_map_stop first")
          return
        end

        begin
          svr.start(host: host, port: port, interval: interval, limits: limits)
        rescue Errno::EADDRINUSE
          print_error("Port #{port} is already in use on #{host}")
          return
        rescue StandardError => e
          print_error("Failed to start server: #{e.class}: #{e.message}")
          return
        end

        if svr.loopback?
          print_status("Serving live network graph at #{svr.url} (loopback only)")
        else
          print_warning("Serving live network graph at #{svr.url} bound to #{host}")
          print_warning('Anyone who can reach this port can watch your engagement data - bind 127.0.0.1 unless you mean it')
        end
        print_status("Polling the database every #{interval}s and pushing changes to browsers over websockets")
        unless framework.db.active
          print_warning('No database connected yet - the map will stay empty until db_connect and data exists')
        end
        print_good("Live network map started on port #{port}")
      end

      def cmd_network_map_stop
        svr = server
        if svr.nil? || !svr.running?
          print_error('Live network map server is not running')
          return
        end
        svr.stop
        print_good('Live network map server stopped')
      end

      def cmd_network_map_status
        svr = server
        if svr.nil?
          print_error('network_map plugin is not fully loaded')
          return
        end
        st = svr.status
        if st[:running]
          print_line 'Status:    running'
          print_line "URL:       http://#{st[:host]}:#{st[:port]}/"
          print_line "Clients:   #{st[:clients]} browser(s) connected"
          print_line "Interval:  #{st[:interval]}s poll"
          print_line "Database:  #{st[:db_active] ? "active (workspace #{st[:workspace]})" : 'not connected'}"
          if st[:db_active] && st[:counts]
            c = st[:counts]
            print_line "Data:      #{c[:hosts]} hosts, #{c[:services]} services, #{c[:sessions]} sessions, #{c[:loot]} loot, #{c[:vulns]} vulns"
          end
        else
          print_line 'Status:    stopped'
          print_line "Database:  #{st[:db_active] ? "active (workspace #{st[:workspace]})" : 'not connected'}"
        end
      end
    end

    def initialize(framework, opts)
      super
      self.class.server = LiveServer.new(framework, self)
      @console_state = { version: 0, last_command: nil, tail: [] }
      @console_mutex = ::Mutex.new
      @console_driver = opts['ConsoleDriver']
      if @console_driver
        @console_driver.instance_variable_set(:@network_map_tap, method(:record_console_line))
        @console_driver.extend(ConsoleTapMethods)
      end
      @relay = EventRelay.new(self.class.server)
      framework.events.add_db_subscriber(@relay)
      framework.events.add_session_subscriber(@relay)
      # on_module_run / on_module_complete arrive through general subscribers
      framework.events.add_general_subscriber(@relay)
      # on_ui_command (console commands) goes only to ui_event_subscribers
      framework.events.add_ui_subscriber(@relay)
      add_console_dispatcher(CommandDispatcher)
      print_status('network_map loaded - run network_map_start [port] to serve the live graph')
    end

    # Tees console output into a small ring buffer so the MSF node can show
    # operator activity.  Lines are recorded by ConsoleTapMethods on the
    # driver (prefixed + color-tokenized).  Commands ride the framework's
    # on_ui_command event instead of the driver hook, which every dispatcher
    # instantiation overwrites (see EventRelay).
    def record_console_command(line)
      record_console_line("> #{line}")
      @console_mutex.synchronize do
        @console_state[:last_command] = line
      end
    rescue StandardError
      nil
    end

    def record_console_line(line)
      @console_mutex.synchronize do
        st = @console_state
        st[:tail].push(line)
        st[:tail].shift while st[:tail].length > CONSOLE_TAIL_MAX
        st[:version] += 1
      end
    rescue StandardError
      nil
    end

    def console_snapshot
      @console_mutex.synchronize do
        {
          last_command: @console_state[:last_command],
          tail: @console_state[:tail].dup
        }
      end
    end

    # Bumped on every captured line; the poller folds it into its fingerprint
    # so console activity pushes to browsers without touching the database.
    def console_activity_version
      @console_mutex.synchronize { @console_state[:version] }
    end

    def cleanup
      svr = self.class.server
      svr&.stop
      begin
        framework.events.remove_db_subscriber(@relay)
        framework.events.remove_session_subscriber(@relay)
        framework.events.remove_general_subscriber(@relay)
        framework.events.remove_ui_subscriber(@relay)
      rescue StandardError
        nil
      end
      # neutralize the console tap (module stays extended but records nothing)
      @console_driver&.instance_variable_set(:@network_map_tap, nil)
      self.class.server = nil
      remove_console_dispatcher('network_map')
    end

    # Plugin prints normally bypass the driver (Plugin#output is the raw
    # output object), which would leave this plugin's own status lines out
    # of the captured tail.  Route them through the driver when present so
    # the browser console shows exactly what the operator's terminal does.
    def tap_status(msg)
      if @console_driver&.respond_to?(:print_status)
        @console_driver.print_status(msg)
      else
        print_status(msg)
      end
    end

    def tap_warning(msg)
      if @console_driver&.respond_to?(:print_warning)
        @console_driver.print_warning(msg)
      else
        print_warning(msg)
      end
    end

    def name
      'network_map'
    end

    def desc
      'Live-updating network topology web server - serves the network_graph visualization and pushes database changes to browsers over websockets'
    end
  end
end

class Msf::Plugin::NetworkMapLive
  # Served at "/".  Adapted from the network_graph module's HTML template
  # (data/auxiliary/analyze/network_map/network_map_template.html): instead of
  # baked-in %%NODES%%/%%LINKS%%, data is fetched from /graph.json and then
  # kept current over the /ws websocket, preserving node positions across
  # updates.
  INDEX_HTML = <<~'HTML'
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>MSF Network Graph - Live</title>
      <script src="/d3.js"></script>
      <script>
        if (typeof d3 === 'undefined') {
          document.write('<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js" crossorigin="anonymous"><\/script>');
        }
      </script>
      <style>
        :root {
          --bg-canvas:        #0d1117;
          --bg-surface:       #161b22;
          --bg-elevated:      #21262d;
          --bg-surface-alpha: rgba(22, 27, 34, 0.93);
          --bg-tooltip:       rgba(22, 27, 34, 0.95);
          --border:           #30363d;
          --text-primary:     #e6edf3;
          --text-secondary:   #c9d1d9;
          --text-muted:       #8b949e;
          --accent:           #58a6ff;
          --route-hop:        #79c0ff;
          --graph-edge:       #30363d;
        }
        body.light {
          --bg-canvas:        #f6f8fa;
          --bg-surface:       #ffffff;
          --bg-elevated:      #f6f8fa;
          --bg-surface-alpha: rgba(255, 255, 255, 0.95);
          --bg-tooltip:       rgba(255, 255, 255, 0.97);
          --border:           #d0d7de;
          --text-primary:     #1f2328;
          --text-secondary:   #24292f;
          --text-muted:       #57606a;
          --accent:           #0969da;
          --route-hop:        #0550ae;
          --graph-edge:       #b8c0cc;
        }
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          background: var(--bg-canvas);
          color: var(--text-secondary);
          display: flex;
          height: 100vh;
          overflow: hidden;
        }
        #graph-container {
          flex: 1;
          position: relative;
          overflow: hidden;
          background: var(--bg-canvas);
        }
        #svg {
          width: 100%;
          height: 100%;
        }
        #sidebar {
          width: 300px;
          min-width: 300px;
          background: var(--bg-surface);
          border-left: 1px solid var(--border);
          overflow-y: auto;
          padding: 0;
          transition: transform 0.2s ease;
        }
        #sidebar.hidden {
          transform: translateX(100%);
          width: 0;
          min-width: 0;
          padding: 0;
          border: none;
          overflow: hidden;
        }
        #sidebar-header {
          background: var(--bg-elevated);
          padding: 14px 16px;
          border-bottom: 1px solid var(--border);
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        #sidebar-header h3 {
          font-size: 14px;
          font-weight: 600;
          color: var(--text-primary);
        }
        #sidebar-close {
          background: none;
          border: none;
          color: var(--text-muted);
          cursor: pointer;
          font-size: 18px;
          line-height: 1;
          padding: 0 4px;
        }
        #sidebar-close:hover { color: var(--text-primary); }
        #sidebar-content { padding: 16px; }
        .detail-group { margin-bottom: 16px; }
        .detail-label {
          font-size: 11px;
          font-weight: 600;
          color: var(--text-muted);
          text-transform: uppercase;
          letter-spacing: 0.8px;
          margin-bottom: 4px;
        }
        .detail-value {
          font-size: 13px;
          color: var(--text-primary);
          word-break: break-all;
        }
        .badge {
          display: inline-block;
          padding: 2px 8px;
          border-radius: 12px;
          font-size: 11px;
          font-weight: 600;
          margin: 2px 2px 2px 0;
        }
        .badge-compromised { background: #da3633; color: #fff; }
        .badge-ever-compromised { background: #7d1f1f; color: #fff; }
        .badge-session { background: #1f6feb; color: #fff; }
        .badge-closed { background: var(--bg-elevated); color: var(--text-muted); }
        .badge-port { background: #238636; color: #fff; }
        .session-entry {
          background: var(--bg-elevated);
          border: 1px solid var(--border);
          border-radius: 6px;
          padding: 8px 10px;
          margin-bottom: 6px;
          font-size: 12px;
        }
        .session-active { border-left: 3px solid #da3633; }
        .session-closed { border-left: 3px solid var(--border); opacity: 0.7; }
        .services-list {
          display: flex;
          flex-wrap: wrap;
          gap: 4px;
        }
        .loot-entry {
          background: var(--bg-elevated);
          border: 1px solid var(--border);
          border-left: 3px solid #8957e5;
          border-radius: 6px;
          padding: 7px 10px;
          margin-bottom: 6px;
          font-size: 12px;
          cursor: pointer;
          text-decoration: none;
          display: block;
          color: inherit;
        }
        .loot-entry:hover { border-color: #a371f7; background: var(--bg-elevated); filter: brightness(0.95); }
        .loot-entry .loot-info { color: #a371f7; font-weight: 600; margin-bottom: 2px; }
        .loot-entry .loot-meta { color: var(--text-muted); font-size: 11px; margin-top: 2px; }
        .loot-entry .loot-name { color: var(--text-secondary); font-weight: normal; margin-top: 2px; font-size: 11px; }
        .link {
          fill: none;
          stroke: var(--graph-edge);
          stroke-width: 1.5;
          stroke-opacity: 0.8;
        }
        .link.highlighted {
          fill: none;
          stroke: #f85149;
          stroke-width: 3;
          stroke-opacity: 1;
        }
        .link.dimmed { stroke-opacity: 0.15; }
        .node-group { cursor: pointer; }
        .node-circle {
          stroke: var(--accent);
          stroke-width: 2;
          transition: filter 0.1s;
        }
        .node-group:hover .node-circle {
          filter: brightness(1.4);
        }
        .node-group.dimmed { opacity: 0.25; }
        .node-group.filter-hidden { display: none; }
        .node-group.filter-dimmed { opacity: 0.2; }
        .link.filter-hidden { display: none; }
        .link.filter-dimmed { stroke-opacity: 0.08; }
        .node-group.selected .node-circle {
          stroke-width: 3;
          filter: brightness(1.3);
        }
        .node-label {
          font-size: 11px;
          fill: var(--text-muted);
          pointer-events: none;
          text-anchor: middle;
        }
        #live-status {
          position: absolute;
          top: 12px;
          left: 50%;
          transform: translateX(-50%);
          background: var(--bg-surface-alpha);
          border: 1px solid var(--border);
          border-radius: 14px;
          padding: 6px 14px;
          font-size: 12px;
          color: var(--text-secondary);
          display: flex;
          align-items: center;
          gap: 8px;
          z-index: 100;
          white-space: nowrap;
        }
        #live-status .dot {
          width: 9px;
          height: 9px;
          border-radius: 50%;
          background: #8b949e;
          flex-shrink: 0;
        }
        #live-status .dot.live { background: #3fb950; animation: dot-pulse 2s infinite; }
        #live-status .dot.polling { background: #e3b341; }
        #live-status .dot.off { background: #f85149; }
        #live-status .sep { color: var(--text-muted); opacity: 0.5; }
        #live-status .live-label { font-weight: 700; letter-spacing: 0.5px; }
        #live-status .live-label.live { color: #3fb950; }
        #live-status .live-label.polling { color: #e3b341; }
        #live-status .live-label.off { color: #f85149; }
        @keyframes dot-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.35; } }
        #nodb-banner {
          position: absolute;
          top: 48px;
          left: 50%;
          transform: translateX(-50%);
          background: rgba(227, 179, 65, 0.12);
          border: 1px solid #e3b341;
          border-radius: 8px;
          padding: 6px 14px;
          font-size: 12px;
          color: #e3b341;
          display: none;
          z-index: 100;
        }
        .node-group.just-added .node-circle { animation: pulse-new 1.1s ease-out 5; }
        @keyframes pulse-new {
          0% { stroke: #3fb950; stroke-width: 2; }
          45% { stroke: #3fb950; stroke-width: 9; }
          100% { stroke: var(--accent); stroke-width: 2; }
        }
        .node-group.flash-comp .node-circle { animation: flash-comp 0.5s ease-in-out 6; }
        @keyframes flash-comp { 50% { filter: brightness(2) drop-shadow(0 0 8px #f85149); } }
        #legend {
          position: absolute;
          top: 12px;
          left: 12px;
          background: var(--bg-surface-alpha);
          border: 1px solid var(--border);
          border-radius: 8px;
          padding: 12px 14px;
          min-width: 150px;
          font-size: 12px;
        }
        #legend h4 {
          color: var(--text-primary);
          font-size: 12px;
          margin-bottom: 8px;
          font-weight: 600;
          display: flex;
          justify-content: space-between;
          align-items: center;
          cursor: pointer;
          user-select: none;
        }
        #legend-toggle {
          background: none;
          border: none;
          color: var(--text-muted);
          cursor: pointer;
          font-size: 14px;
          line-height: 1;
          padding: 0 0 0 8px;
        }
        #legend-toggle:hover { color: var(--text-primary); }
        #legend.collapsed { padding-bottom: 10px; }
        #legend.collapsed #legend-body { display: none; }
        #legend.collapsed h4 { margin-bottom: 0; }
        .legend-item {
          display: flex;
          align-items: center;
          gap: 7px;
          margin-bottom: 5px;
          color: var(--text-muted);
        }
        .legend-dot {
          width: 12px;
          height: 12px;
          border-radius: 50%;
          flex-shrink: 0;
        }
        .legend-separator {
          margin-top: 6px;
          border-top: 1px solid var(--border);
          padding-top: 6px;
        }
        .legend-hint {
          color: var(--text-secondary);
          font-size: 11px;
          margin-top: 4px;
        }
        .os-cat-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 3px 8px 3px;
          font-size: 10px;
          font-weight: 700;
          color: var(--text-muted);
          text-transform: uppercase;
          letter-spacing: 0.8px;
          cursor: pointer;
          user-select: none;
        }
        .os-cat-sep { border-top: 1px solid var(--border); margin-top: 4px; padding-top: 6px; }
        .os-cat-arrow { font-size: 9px; }
        .os-cat-body.collapsed { display: none; }
        #theme-toggle {
          position: absolute;
          top: 12px;
          right: 12px;
          background: var(--bg-surface-alpha);
          border: 1px solid var(--border);
          border-radius: 6px;
          color: var(--text-muted);
          cursor: pointer;
          font-size: 16px;
          line-height: 1;
          padding: 5px 8px;
          z-index: 100;
          transition: color 0.15s, background 0.15s;
        }
        #theme-toggle:hover { color: var(--text-primary); background: var(--bg-elevated); }
        #export-btn {
          position: absolute;
          bottom: 14px;
          right: 12px;
          background: var(--bg-elevated);
          color: var(--text-secondary);
          border: 1px solid var(--border);
          border-radius: 6px;
          padding: 6px 12px;
          cursor: pointer;
          font-size: 12px;
          font-family: inherit;
          z-index: 100;
        }
        #export-btn:hover { background: var(--border); color: var(--text-primary); }
        #bottom-controls {
          position: absolute;
          bottom: 14px;
          left: 12px;
          display: flex;
          flex-direction: column;
          align-items: flex-start;
          gap: 6px;
          z-index: 100;
        }
        .ctrl-btn {
          background: var(--bg-elevated);
          color: var(--text-secondary);
          border: 1px solid var(--border);
          border-radius: 6px;
          padding: 6px 12px;
          cursor: pointer;
          font-size: 12px;
          font-family: inherit;
        }
        .ctrl-btn:hover { background: var(--border); color: var(--text-primary); }
        #configure-toggle {
          background: var(--bg-elevated);
          color: var(--text-secondary);
          border: 1px solid var(--border);
          border-radius: 6px;
          padding: 6px 12px;
          cursor: pointer;
          font-size: 12px;
          font-family: inherit;
          display: flex;
          align-items: center;
          gap: 6px;
          white-space: nowrap;
        }
        #configure-toggle:hover { background: var(--border); color: var(--text-primary); }
        #configure-body {
          display: none;
          background: var(--bg-surface);
          border: 1px solid var(--border);
          border-radius: 8px;
          padding: 12px 14px;
          min-width: 210px;
          box-shadow: 0 -4px 20px rgba(0,0,0,0.3);
        }
        .config-row {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-bottom: 10px;
        }
        .config-label { font-size: 12px; color: var(--text-muted); flex: 1; }
        .config-input {
          background: var(--bg-canvas);
          border: 1px solid var(--border);
          border-radius: 4px;
          color: var(--text-secondary);
          font-size: 12px;
          padding: 3px 6px;
          width: 58px;
          text-align: center;
        }
        .config-input:focus { outline: none; border-color: var(--accent); }
        .config-btn {
          background: var(--bg-elevated);
          color: var(--text-secondary);
          border: 1px solid var(--border);
          border-radius: 6px;
          padding: 6px 10px;
          cursor: pointer;
          font-size: 12px;
          font-family: inherit;
          width: 100%;
          text-align: left;
        }
        .config-btn:hover { background: var(--border); color: var(--text-primary); }
        .config-divider { height: 1px; background: var(--border); margin: 8px 0; }
        .config-toggle {
          display: flex;
          align-items: center;
          gap: 8px;
          cursor: pointer;
          font-size: 12px;
          color: var(--text-secondary);
          user-select: none;
        }
        .config-toggle input[type="checkbox"] {
          width: 14px;
          height: 14px;
          cursor: pointer;
          accent-color: #388bfd;
        }
        #type-popup {
          position: fixed;
          background: var(--bg-surface);
          border: 1px solid var(--border);
          border-radius: 8px;
          padding: 10px;
          display: none;
          z-index: 200;
          box-shadow: 0 8px 24px rgba(0,0,0,0.4);
          min-width: 170px;
          overflow: visible;
        }
        .configure-row {
          justify-content: space-between;
        }
        #configure-submenu {
          display: none;
          position: absolute;
          left: calc(100% + 6px);
          top: 0;
          background: var(--bg-surface);
          border: 1px solid var(--border);
          border-radius: 8px;
          padding: 10px;
          min-width: 220px;
          max-height: 400px;
          overflow-y: auto;
          box-shadow: 0 8px 24px rgba(0,0,0,0.4);
          z-index: 210;
        }
        #type-popup h4 {
          font-size: 11px;
          color: var(--text-muted);
          text-transform: uppercase;
          letter-spacing: 0.8px;
          margin-bottom: 8px;
          font-weight: 600;
        }
        .type-opt {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 5px 8px;
          border-radius: 5px;
          cursor: pointer;
          font-size: 13px;
          color: var(--text-secondary);
        }
        .type-opt:hover { background: var(--bg-elevated); }
        .type-opt.active { color: var(--accent); }
        .popup-divider { height: 1px; background: var(--border); margin: 8px 0; }
        .color-row {
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 4px 8px;
        }
        .color-row input[type="color"] {
          width: 36px;
          height: 26px;
          border: 1px solid var(--border);
          border-radius: 4px;
          background: none;
          cursor: pointer;
          padding: 2px;
        }
        .color-row button {
          background: var(--bg-elevated);
          color: var(--text-secondary);
          border: 1px solid var(--border);
          border-radius: 4px;
          padding: 3px 8px;
          cursor: pointer;
          font-size: 12px;
          font-family: inherit;
        }
        .color-row button:hover { background: var(--border); }
        .collapsible-label {
          display: flex;
          justify-content: space-between;
          align-items: center;
          cursor: pointer;
          user-select: none;
        }
        .section-toggle {
          background: none;
          border: none;
          color: var(--text-muted);
          cursor: pointer;
          font-size: 10px;
          padding: 0 0 0 6px;
          line-height: 1;
        }
        .section-toggle:hover { color: var(--text-primary); }
        .collapsible-body.collapsed { display: none; }
        .route-list { font-family: monospace; font-size: 12px; line-height: 1.8; }
        .route-entry-first { color: var(--text-primary); font-weight: 600; }
        .route-entry-hop { color: var(--route-hop); padding-left: 10px; }
        .route-entry-hop::before { content: '\2192\00a0'; color: var(--text-muted); }
        .rtt-label { color: var(--text-muted); font-size: 10px; margin-left: 4px; }
        .rtt-total { color: var(--text-secondary); font-style: italic; }
        .session-meta { color: var(--text-muted); font-size: 11px; }
        .module-entry { font-family: monospace; font-size: 11px; color: var(--text-secondary); padding: 2px 0; word-break: break-all; }
        .vuln-entry { padding: 5px 0; border-bottom: 1px solid var(--border); }
        .vuln-entry:last-child { border-bottom: none; }
        .vuln-name { color: #e3b341; font-weight: 600; font-size: 12px; }
        .vuln-info { color: var(--text-muted); font-size: 11px; margin-top: 2px; }
        .vuln-refs { margin-top: 3px; display: flex; flex-wrap: wrap; gap: 4px; }
        .vuln-ref { background: var(--bg-elevated); border: 1px solid var(--border); border-radius: 3px; padding: 1px 5px; font-size: 10px; color: var(--text-secondary); font-family: monospace; }
        .vuln-exploited { color: #f85149; font-size: 11px; margin-top: 2px; }
        .cred-entry {
          background: var(--bg-elevated);
          border: 1px solid var(--border);
          border-left: 3px solid #f0883e;
          border-radius: 6px;
          padding: 7px 10px;
          margin-bottom: 6px;
          font-size: 12px;
        }
        .cred-username { color: #f0883e; font-weight: 600; margin-bottom: 2px; font-family: monospace; }
        .cred-meta { color: var(--text-muted); font-size: 11px; }
        .cred-status { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px; padding: 1px 5px; border-radius: 3px; margin-left: 4px; }
        .cred-status-successful { background: rgba(63,185,80,0.15); color: #3fb950; }
        .cred-status-untried    { background: rgba(139,148,158,0.15); color: #8b949e; }
        .cred-status-denied     { background: rgba(248,81,73,0.15); color: #f85149; }
        .session-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 3px; }
        .job-entry {
          background: var(--bg-elevated);
          border: 1px solid var(--border);
          border-left: 3px solid #238636;
          border-radius: 6px;
          padding: 7px 10px;
          margin-bottom: 6px;
          font-size: 12px;
          word-break: break-all;
        }
        .job-entry .job-id {
          font-family: monospace;
          font-weight: 700;
          color: #3fb950;
          margin-right: 4px;
        }
        #console-panel {
          position: absolute;
          bottom: 14px;
          left: 50%;
          transform: translateX(-50%);
          width: max(320px, min(720px, calc(100% - 420px)));
          background: var(--bg-surface-alpha);
          border: 1px solid var(--border);
          border-radius: 8px;
          z-index: 100;
          font-size: 12px;
        }
        #console-header {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 6px 12px;
          cursor: pointer;
          user-select: none;
          color: var(--text-secondary);
        }
        #console-header:hover { background: var(--bg-elevated); border-radius: 8px; }
        .console-title {
          font-weight: 600;
          color: var(--text-primary);
          font-size: 12px;
          white-space: nowrap;
        }
        #console-preview {
          flex: 1;
          font-family: monospace;
          font-size: 11px;
          color: var(--accent);
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        #console-toggle {
          background: none;
          border: none;
          color: var(--text-muted);
          cursor: pointer;
          font-size: 14px;
          line-height: 1;
          padding: 0 4px;
        }
        #console-toggle:hover { color: var(--text-primary); }
        #console-panel.collapsed #console-body { display: none; }
        #console-body {
          font-family: monospace;
          font-size: 11px;
          color: var(--text-secondary);
          background: var(--bg-surface);
          border-top: 1px solid var(--border);
          border-radius: 0 0 8px 8px;
          padding: 8px 12px;
          max-height: 30vh;
          overflow-y: auto;
          white-space: pre-wrap;
          word-break: break-all;
        }
        .console-line { min-height: 14px; }
        .console-line.cmd { color: var(--accent); }
        /* msf %token palette (rex-text substitute_colors) */
        .tk-red { color: #f85149; } .tk-grn { color: #3fb950; }
        .tk-blu { color: #58a6ff; } .tk-yel { color: #e3b341; }
        .tk-mag { color: #bc8cff; } .tk-cya { color: #39c5cf; }
        .tk-whi { color: #e6edf3; } .tk-blk { color: #484f58; }
        .tk-dred { color: #a61e2d; } .tk-dgrn { color: #1a7f37; }
        .tk-dblu { color: #0550ae; } .tk-dyel { color: #9e6a03; }
        .tk-dcya { color: #1b7c83; } .tk-dwhi { color: #6e7681; }
        .tk-dmag { color: #8250df; }
        .tk-bld { font-weight: 700; }
        .tk-und { text-decoration: underline; }
        .tk-bgred { background: rgba(248, 81, 73, 0.25); }
        .tk-bggrn { background: rgba(63, 185, 80, 0.25); }
        .tk-bgblu { background: rgba(88, 166, 255, 0.25); }
        .tk-bgyel { background: rgba(227, 179, 65, 0.25); }
        .tk-bgmag { background: rgba(188, 140, 255, 0.25); }
        .tk-bgcyn { background: rgba(57, 197, 207, 0.25); }
        .tk-bgwhi { background: rgba(230, 237, 243, 0.2); }
        .tk-bgblk { background: rgba(72, 79, 88, 0.4); }
        .copy-session-btn {
          background: var(--bg-elevated);
          border: 1px solid var(--border);
          border-radius: 4px;
          color: var(--text-muted);
          cursor: pointer;
          font-size: 11px;
          padding: 1px 5px;
          line-height: 1.4;
          flex-shrink: 0;
        }
        .copy-session-btn:hover { background: var(--border); color: var(--text-primary); }
        #filter-panel { display: flex; flex-direction: column; align-items: flex-start; }
        #filter-body {
          display: none;
          background: var(--bg-surface);
          border: 1px solid var(--border);
          border-radius: 8px;
          padding: 12px 14px;
          min-width: 220px;
          max-height: 420px;
          overflow-y: auto;
          box-shadow: 0 -4px 20px rgba(0,0,0,0.3);
          margin-bottom: 4px;
        }
        #filter-toggle {
          background: var(--bg-elevated);
          color: var(--text-secondary);
          border: 1px solid var(--border);
          border-radius: 6px;
          padding: 6px 12px;
          cursor: pointer;
          font-size: 12px;
          font-family: inherit;
          display: flex;
          align-items: center;
          gap: 6px;
          white-space: nowrap;
        }
        #filter-toggle:hover { background: var(--border); color: var(--text-primary); }
        #filter-toggle.active { border-color: var(--accent); color: var(--accent); }
        .filter-mode-row { display: flex; gap: 12px; margin-bottom: 10px; }
        .filter-mode-row label { display: flex; align-items: center; gap: 4px; font-size: 12px; color: var(--text-secondary); cursor: pointer; }
        .filter-section { margin-bottom: 10px; }
        .filter-section-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 5px; }
        .filter-opt { display: flex; align-items: center; gap: 5px; font-size: 12px; color: var(--text-secondary); cursor: pointer; margin-bottom: 3px; white-space: nowrap; }
        .filter-opt input { cursor: pointer; accent-color: var(--accent); }
        #filter-ports, #filter-module-search, #filter-cred-search { width: 100%; box-sizing: border-box; }
        #tooltip {
          position: fixed;
          background: var(--bg-tooltip);
          border: 1px solid var(--border);
          border-radius: 6px;
          padding: 6px 10px;
          font-size: 12px;
          pointer-events: none;
          display: none;
          z-index: 300;
          color: var(--text-secondary);
        }
      </style>
    </head>
    <body>
      <div id="graph-container">
        <svg id="svg"></svg>
        <button id="theme-toggle" title="Toggle light/dark mode" onclick="toggleTheme()">&#x263D;</button>
        <div id="live-status">
          <span class="dot off" id="live-dot"></span>
          <span class="live-label" id="live-label">CONNECTING</span>
          <span class="sep">|</span>
          <span id="live-counts">loading...</span>
          <span class="sep">|</span>
          <span id="live-updated">--</span>
          <span class="sep">|</span>
          <span id="live-clients"></span>
        </div>
        <div id="nodb-banner">No database connected - run db_connect in msfconsole; this page picks it up automatically.</div>
        <div id="console-panel" class="collapsed">
          <div id="console-header" onclick="toggleConsolePanel()" title="Show/hide msfconsole activity">
            <span class="console-title">Console</span>
            <span id="console-preview"></span>
            <button id="console-toggle">&#x25b2;</button>
          </div>
          <div id="console-body"></div>
        </div>
        <div id="legend">
          <h4>Legend <button id="legend-toggle" title="Minimize legend">&#x2212;</button></h4>
          <div id="legend-body">
            <div class="legend-item">
              <svg width="14" height="14" style="flex-shrink:0;display:block">
                <use href="#icon-msf" width="14" height="14"/>
              </svg>
              MSF Framework
            </div>
            <div class="legend-item"><div class="legend-dot" style="background:#da3633"></div> Active Session</div>
            <div class="legend-item"><div class="legend-dot" style="background:#7d1f1f"></div> Previously Compromised</div>
            <div class="legend-item"><div class="legend-dot" style="background:#388bfd"></div> Discovered</div>
            <div class="legend-item legend-separator">
              <div style="width:24px;height:2px;background:#f85149;border-radius:1px"></div> Active path
            </div>
            <div class="legend-item legend-hint">Right-click node to change type/color</div>
          </div>
        </div>
        <div id="bottom-controls">
          <button class="ctrl-btn" id="btn-deselect" style="display:none">Clear Selection</button>
          <div id="filter-panel">
            <div id="filter-body">
              <div class="filter-mode-row">
                <label><input type="radio" name="filter-mode" value="dim" checked> Dim</label>
                <label><input type="radio" name="filter-mode" value="hide"> Hide</label>
              </div>
              <div class="config-divider"></div>
              <div class="filter-section">
                <div class="filter-section-label">Session</div>
                <label class="filter-opt"><input type="checkbox" class="filter-session" value="active"> Active session</label>
                <label class="filter-opt"><input type="checkbox" class="filter-session" value="ever"> Ever compromised</label>
              </div>
              <div class="filter-section">
                <div class="filter-section-label">Device Type</div>
                <div id="filter-device-opts"></div>
              </div>
              <div class="filter-section">
                <div class="filter-section-label">Operating System</div>
                <div id="filter-os-opts"></div>
              </div>
              <div class="filter-section">
                <div class="filter-section-label">Ports (comma-separated)</div>
                <input type="text" id="filter-ports" class="config-input" placeholder="80, 443, 3306...">
              </div>
              <div class="filter-section">
                <div class="filter-section-label">Modules Used</div>
                <input type="text" id="filter-module-search" class="config-input" placeholder="Search modules..." oninput="filterModuleList(this.value)">
                <div id="filter-module-opts"></div>
              </div>
              <div class="filter-section">
                <div class="filter-section-label">Credentials</div>
                <label class="filter-opt"><input type="checkbox" class="filter-cred-has" value="has_creds"> Has credentials</label>
                <label class="filter-opt"><input type="checkbox" class="filter-cred-status" value="Successful"> Successful</label>
                <label class="filter-opt"><input type="checkbox" class="filter-cred-status" value="Untried"> Untried</label>
                <input type="text" id="filter-cred-search" class="config-input" placeholder="Search username..." oninput="filterCredList(this.value)" style="margin-top:4px">
                <div id="filter-cred-opts"></div>
              </div>
              <div class="config-divider"></div>
              <button class="config-btn" id="btn-filter-clear">Clear Filters</button>
            </div>
            <button id="filter-toggle" onclick="toggleFilter()">Filter <span id="filter-arrow">&#x25b2;</span></button>
          </div>
          <div id="configure-panel">
            <div id="configure-body">
              <div class="config-row">
                <span class="config-label">Direction</span>
                <div style="display:flex;gap:8px">
                  <label class="filter-opt"><input type="radio" name="layout-dir" value="top-down" checked> Top Down</label>
                  <label class="filter-opt"><input type="radio" name="layout-dir" value="left-right"> Left &#x2192; Right</label>
                </div>
              </div>
              <div class="config-row">
                <span class="config-label">Nodes per layer</span>
                <input type="number" class="config-input" id="cfg-nodes-per-row" min="1" max="100" placeholder="auto">
              </div>
              <div class="config-divider"></div>
              <button class="config-btn" id="btn-reset">&#x21ba; Reset Layout &amp; View</button>
              <div class="config-divider"></div>
              <label class="config-toggle">
                <input type="checkbox" id="cfg-physics" checked>
                <span>Physics enabled</span>
              </label>
            </div>
            <button id="configure-toggle" onclick="toggleConfigure()">Configure <span id="cfg-arrow">&#x25b2;</span></button>
          </div>
        </div>
        <button id="export-btn" onclick="exportImage()" title="Export graph as PNG">&#x2913; Export PNG</button>
        <div id="type-popup">
          <h4>Change Device Type</h4>
          <div id="type-opts"></div>
          <div class="popup-divider"></div>
          <div class="type-opt configure-row" onclick="toggleSubmenu(event)">
            <span style="flex:1">Configure</span>
            <span id="submenu-arrow">&#x25b6;</span>
          </div>
          <div id="configure-submenu" onclick="event.stopPropagation()">
            <h4>Node Color</h4>
            <div class="color-row">
              <input type="color" id="node-color-picker" value="#388bfd">
              <button onclick="applyColorChange()">Apply</button>
              <button onclick="resetNodeColor()">Reset</button>
            </div>
            <div class="popup-divider"></div>
            <h4>OS Icon</h4>
            <div id="os-opts"></div>
          </div>
        </div>
        <div id="tooltip"></div>
      </div>
      <div id="sidebar" class="hidden">
        <div id="sidebar-header">
          <h3 id="sidebar-title">Node Details</h3>
          <button id="sidebar-close">&times;</button>
        </div>
        <div id="sidebar-content"></div>
      </div>

      <script>
    (function() {
      if (typeof d3 === 'undefined') {
        document.getElementById('live-counts').textContent = 'd3.js failed to load (offline?)';
        document.getElementById('live-label').textContent = 'ERROR';
        return;
      }
      // ---- live data state ----
      let firstLoad = true;
      let lastRaw = null;
      let simNodes = [];
      let simLinks = [];
      let nodeById = {};
      let nodeDepth = {};
      let linkSel = null;
      let nodeGroup = null;
      let selectedNodeId = null;
      const nodeColorOverride = {};
      const nodeTypeOverride = {};
      const nodeOsOverride = {};
      let maxPerRowOverride = null;
      let layoutDirection = 'top-down';

      const DEVICE_TYPES = ['computer', 'server', 'router', 'switch', 'firewall', 'phone', 'printer', 'msf', 'generic'];
      const OS_CATEGORIES = [
        { name: 'Computers',  keys: ['android', 'bsd', 'debian', 'ios', 'linux', 'macos', 'redhat', 'ubuntu', 'vmware', 'windows'] },
        { name: 'Networking', keys: ['arista', 'aruba', 'asus', 'cisco', 'eero', 'fortinet', 'huawei', 'juniper', 'linksys', 'meraki', 'mikrotik', 'netgear', 'paloalto', 'tplink', 'ubiquiti'] },
        { name: 'Storage',    keys: ['buffalo', 'qnap', 'synology'] }
      ];
      const OS_FAMILIES = OS_CATEGORIES.flatMap(c => c.keys);
      const osLabels = {
        android: 'Android',        bsd: 'BSD / FreeBSD',      debian: 'Debian',
        ios: 'iPhone / iOS',       linux: 'Linux',             macos: 'macOS',
        redhat: 'Red Hat / CentOS', ubuntu: 'Ubuntu',          vmware: 'VMware / ESXi',
        windows: 'Windows',
        arista: 'Arista EOS',      aruba: 'HPE Aruba',         asus: 'ASUS',
        cisco: 'Cisco',            eero: 'Amazon Eero',        fortinet: 'Fortinet',
        huawei: 'Huawei',          juniper: 'Juniper / JunOS', linksys: 'Linksys',
        meraki: 'Cisco Meraki',    mikrotik: 'MikroTik',       netgear: 'Netgear',
        paloalto: 'Palo Alto',     tplink: 'TP-Link',          ubiquiti: 'Ubiquiti',
        buffalo: 'Buffalo',        qnap: 'QNAP',               synology: 'Synology'
      };

      const NODE_COLORS = {
        msf:      '#1b92ff',
        compromised: '#da3633',
        ever_compromised: '#7d1f1f',
        default:  '#388bfd'
      };

      const ICON_PATHS = {
        computer: `<rect x="2" y="4" width="20" height="13" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/>
                   <line x1="8" y1="21" x2="16" y2="21" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
                   <line x1="12" y1="17" x2="12" y2="21" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>`,
        server:   `<rect x="3" y="2" width="18" height="6" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.8"/>
                   <rect x="3" y="10" width="18" height="6" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.8"/>
                   <rect x="3" y="18" width="18" height="4" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.8"/>
                   <circle cx="19" cy="5" r="1.2" fill="currentColor"/>
                   <circle cx="19" cy="13" r="1.2" fill="currentColor"/>`,
        router:   `<rect x="2" y="11" width="20" height="7" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/>
                   <line x1="7" y1="11" x2="7" y2="7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
                   <line x1="12" y1="11" x2="12" y2="5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
                   <line x1="17" y1="11" x2="17" y2="7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
                   <circle cx="7" cy="5.5" r="1.5" fill="currentColor"/>
                   <circle cx="17" cy="5.5" r="1.5" fill="currentColor"/>
                   <circle cx="19" cy="14.5" r="1" fill="currentColor"/>`,
        switch:   `<rect x="2" y="9" width="20" height="6" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/>
                   <circle cx="6" cy="12" r="1.2" fill="currentColor"/>
                   <circle cx="9.5" cy="12" r="1.2" fill="currentColor"/>
                   <circle cx="13" cy="12" r="1.2" fill="currentColor"/>
                   <circle cx="16.5" cy="12" r="1.2" fill="currentColor"/>
                   <circle cx="20" cy="12" r="1.2" fill="currentColor"/>
                   <line x1="6" y1="9" x2="6" y2="6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
                   <line x1="18" y1="9" x2="18" y2="6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>`,
        firewall: `<path d="M12 2 L4 6 V12 C4 16.5 7.5 20.5 12 22 C16.5 20.5 20 16.5 20 12 V6 Z" fill="none" stroke="currentColor" stroke-width="1.8"/>
                   <line x1="12" y1="8" x2="12" y2="13" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                   <circle cx="12" cy="16" r="1.2" fill="currentColor"/>`,
        phone:    `<rect x="7" y="2" width="10" height="20" rx="2.5" fill="none" stroke="currentColor" stroke-width="1.8"/>
                   <line x1="10" y1="18.5" x2="14" y2="18.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>`,
        printer:  `<rect x="4" y="8" width="16" height="9" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/>
                   <rect x="7" y="15" width="10" height="7" rx="1" fill="none" stroke="currentColor" stroke-width="1.8"/>
                   <rect x="7" y="3" width="10" height="5" rx="1" fill="none" stroke="currentColor" stroke-width="1.8"/>
                   <circle cx="17.5" cy="12" r="1.2" fill="currentColor"/>`,
        generic:  `<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="1.8"/>
                   <path d="M9.5 9.5 C9.5 7.5 14.5 7.5 14.5 10 C14.5 12 12 12.5 12 14" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" fill="none"/>
                   <circle cx="12" cy="17" r="1.2" fill="currentColor"/>`
      };

      const OS_ICONS = {
        windows: `<polygon points="0.5,1 5.5,0.5 5.5,5.5 0.5,5.5" fill="#f25022"/>
                  <polygon points="6.5,0.5 11.5,1 11.5,5.5 6.5,5.5" fill="#7fba00"/>
                  <polygon points="0.5,6.5 5.5,6.5 5.5,11 0.5,11.5" fill="#00a4ef"/>
                  <polygon points="6.5,6.5 11.5,6.5 11.5,11.5 6.5,11" fill="#ffb900"/>`,
        linux:   `<ellipse cx="6" cy="8.5" rx="3.5" ry="3.5" fill="#2c2c2c"/>
                  <ellipse cx="6" cy="9" rx="2" ry="2.5" fill="#f0f0f0"/>
                  <circle cx="6" cy="4" r="2.8" fill="#2c2c2c"/>
                  <ellipse cx="4.9" cy="3.6" rx="0.65" ry="0.75" fill="white"/>
                  <ellipse cx="7.1" cy="3.6" rx="0.65" ry="0.75" fill="white"/>
                  <circle cx="5" cy="3.6" r="0.32" fill="#111"/>
                  <circle cx="7" cy="3.6" r="0.32" fill="#111"/>
                  <polygon points="5.3,5 6.7,5 6,5.8" fill="#ff8c00"/>`,
        redhat:  `<path d="M3,6.5 C3,3 4.2,1.5 6,1.5 C7.8,1.5 9,3 9,6.5 Z" fill="#cc0000"/>
                  <ellipse cx="6" cy="6.5" rx="5" ry="1.5" fill="#ee0000"/>
                  <ellipse cx="6" cy="10.5" rx="3" ry="1.5" fill="#555"/>`,
        debian:  `<path d="M6,1.5 C9.5,1.5 11,4 10.5,6.8 C10,9 8.2,10.5 6,10.5 C4.2,10.5 3,9.2 3,7.5 C3,6 4,5.2 5.5,5.2 C7,5.2 7.8,6.2 7.2,7.2 C6.8,8 5.8,8 5.2,7.5" stroke="#d70751" stroke-width="2" fill="none" stroke-linecap="round"/>`,
        ubuntu:  `<circle cx="6" cy="6" r="5" fill="none" stroke="#e95420" stroke-width="1.5"/>
                  <circle cx="6" cy="1.5" r="1.2" fill="#e95420"/>
                  <circle cx="10.2" cy="8.5" r="1.2" fill="#e95420"/>
                  <circle cx="1.8" cy="8.5" r="1.2" fill="#e95420"/>`,
        macos:   `<path d="M9 3.5 C8 2 6.5 2 5.5 2.5 C5.5 4 6.5 4.5 7 4.5 C6 4.5 4 4.5 3 6.5 C2 8.5 3 11 5.5 11 C6.5 11 7 10.5 8 10.5 C9 10.5 9.5 11 10.5 11 C13 11 14 8.5 13 6.5 C12 4.5 10 4.5 9 4.5 C9.5 4 10 3 9 2 Z" fill="#999"/>
                  <line x1="9" y1="1" x2="9.5" y2="2.5" stroke="#999" stroke-width="1" stroke-linecap="round"/>`,
        vmware:  `<rect x="0.5" y="8.5" width="11" height="3" rx="1" fill="#1d428a"/>
                  <rect x="0.5" y="3.5" width="4.5" height="4.5" rx="0.8" fill="#607078"/>
                  <rect x="1.2" y="4.2" width="3.1" height="2" rx="0.3" fill="#b0bec5"/>
                  <rect x="7" y="3.5" width="4.5" height="4.5" rx="0.8" fill="#607078"/>
                  <rect x="7.7" y="4.2" width="3.1" height="2" rx="0.3" fill="#b0bec5"/>`,
        android: `<rect x="3" y="5" width="6" height="4.5" rx="0.8" fill="#3ddc84"/>
                  <path d="M3.5 5 C3.5 2.8 8.5 2.8 8.5 5" fill="none" stroke="#3ddc84" stroke-width="1.1"/>
                  <circle cx="4.8" cy="4" r="0.45" fill="#fff"/>
                  <circle cx="7.2" cy="4" r="0.45" fill="#fff"/>
                  <line x1="4" y1="3.2" x2="3.2" y2="2.1" stroke="#3ddc84" stroke-width="0.9" stroke-linecap="round"/>
                  <line x1="8" y1="3.2" x2="8.8" y2="2.1" stroke="#3ddc84" stroke-width="0.9" stroke-linecap="round"/>
                  <rect x="1.5" y="6" width="1.2" height="2.8" rx="0.6" fill="#3ddc84"/>
                  <rect x="9.3" y="6" width="1.2" height="2.8" rx="0.6" fill="#3ddc84"/>
                  <rect x="4" y="9.5" width="1.3" height="2" rx="0.5" fill="#3ddc84"/>
                  <rect x="6.7" y="9.5" width="1.3" height="2" rx="0.5" fill="#3ddc84"/>`,
        ios:      `<rect x="2.5" y="0.5" width="7" height="11" rx="1.5" fill="#1c1c1e"/>
                   <rect x="3" y="1.2" width="6" height="8.5" rx="0.8" fill="#2c2c2e"/>
                   <rect x="4" y="0.5" width="4" height="1" rx="0.5" fill="#3a3a3c"/>
                   <rect x="4.5" y="10.3" width="3" height="0.7" rx="0.35" fill="#3a3a3c"/>`,
        bsd:      `<circle cx="6" cy="7" r="4" fill="#ab0000"/>
                   <polygon points="3.5,5 4.5,2 5.3,5" fill="#ab0000"/>
                   <polygon points="8.5,5 7.5,2 6.7,5" fill="#ab0000"/>
                   <circle cx="4.5" cy="6.5" r="0.6" fill="#fff"/>
                   <circle cx="7.5" cy="6.5" r="0.6" fill="#fff"/>
                   <path d="M4.5 8.5 Q6 9.5 7.5 8.5" fill="none" stroke="#fff" stroke-width="0.8" stroke-linecap="round"/>`,
        cisco:    `<rect x="0.5" y="6.5" width="1.3" height="3" rx="0.5" fill="#049fd9"/>
                   <rect x="2.1" y="5" width="1.3" height="4.5" rx="0.5" fill="#049fd9"/>
                   <rect x="3.7" y="3.5" width="1.3" height="6" rx="0.5" fill="#049fd9"/>
                   <rect x="5.3" y="2.5" width="1.3" height="7" rx="0.5" fill="#049fd9"/>
                   <rect x="6.9" y="3.5" width="1.3" height="6" rx="0.5" fill="#049fd9"/>
                   <rect x="8.5" y="5" width="1.3" height="4.5" rx="0.5" fill="#049fd9"/>
                   <rect x="10.1" y="6.5" width="1.3" height="3" rx="0.5" fill="#049fd9"/>`,
        juniper:  `<path d="M5.5 1.5 L8 1.5 L8 9 C8 11.5 4 11.5 3 9.5 L4.5 8.5 C4.8 9.8 6.5 9.8 6.5 9 L6.5 1.5 Z" fill="#84ac28"/>`,
        arista:   `<circle cx="6" cy="6" r="4.8" fill="none" stroke="#00a878" stroke-width="1.5"/>
                   <line x1="6" y1="1.2" x2="6" y2="10.8" stroke="#00a878" stroke-width="1.5"/>
                   <line x1="1.2" y1="6" x2="10.8" y2="6" stroke="#00a878" stroke-width="1.5"/>`,
        fortinet: `<path d="M6 1 L11 3.5 L11 7 C11 9.8 8.5 11.5 6 12 C3.5 11.5 1 9.8 1 7 L1 3.5 Z" fill="#ee3124"/>
                   <path d="M4.5 4 L4.5 9.5 L6 9.5 L6 7.2 L8 7.2 L8 5.8 L6 5.8 L6 5.2 L8.5 5.2 L8.5 4 Z" fill="#fff"/>`,
        aruba:    `<circle cx="6" cy="9.5" r="1.2" fill="#ff8300"/>
                   <path d="M3.8 7.8 Q6 6.2 8.2 7.8" fill="none" stroke="#ff8300" stroke-width="1.3" stroke-linecap="round"/>
                   <path d="M2 5.8 Q6 3 10 5.8" fill="none" stroke="#ff8300" stroke-width="1.3" stroke-linecap="round"/>`,
        ubiquiti: `<path d="M3.5 2 L3.5 7.5 A2.5 2.5 0 0 0 8.5 7.5 L8.5 2" fill="none" stroke="#0059eb" stroke-width="2" stroke-linecap="round"/>`,
        netgear:  `<path d="M2 2 L2 10 L3.5 10 L3.5 5 L7 10 L8.5 10 L8.5 2 L7 2 L7 7 L3.5 2 Z" fill="#6a217f"/>`,
        asus:     `<path d="M6 1 L10.5 11 L1.5 11 Z M6 3.8 L9 10.5 L3 10.5 Z" fill="#004a97" fill-rule="evenodd"/>
                   <rect x="3.8" y="7.5" width="4.4" height="1.3" fill="#004a97"/>`,
        tplink:   `<polygon points="8,1.5 4,7 6.5,7 4.5,10.5 9.5,5 7,5" fill="#01a0e4"/>`,
        synology: `<rect x="2" y="1.5" width="8" height="2.5" rx="0.8" fill="#b5001c"/>
                   <circle cx="8.5" cy="2.75" r="0.7" fill="#fff"/>
                   <rect x="2" y="4.8" width="8" height="2.5" rx="0.8" fill="#b5001c"/>
                   <circle cx="8.5" cy="6.05" r="0.7" fill="#fff"/>
                   <rect x="2" y="8.1" width="8" height="2.5" rx="0.8" fill="#b5001c"/>
                   <circle cx="8.5" cy="9.35" r="0.7" fill="#fff"/>`,
        eero:     `<circle cx="6" cy="2.5" r="1.3" fill="#ff9900"/>
                   <circle cx="2.5" cy="9" r="1.3" fill="#ff9900"/>
                   <circle cx="9.5" cy="9" r="1.3" fill="#ff9900"/>
                   <line x1="6" y1="3.8" x2="3.2" y2="8" stroke="#ff9900" stroke-width="1"/>
                   <line x1="6" y1="3.8" x2="8.8" y2="8" stroke="#ff9900" stroke-width="1"/>
                   <line x1="3.8" y1="9" x2="8.2" y2="9" stroke="#ff9900" stroke-width="1"/>`,
        huawei:   `<ellipse cx="6" cy="6" rx="1.2" ry="4" fill="#cf0a2c" opacity="0.85" transform="rotate(0 6 6)"/>
                   <ellipse cx="6" cy="6" rx="1.2" ry="4" fill="#cf0a2c" opacity="0.85" transform="rotate(45 6 6)"/>
                   <ellipse cx="6" cy="6" rx="1.2" ry="4" fill="#cf0a2c" opacity="0.85" transform="rotate(90 6 6)"/>
                   <ellipse cx="6" cy="6" rx="1.2" ry="4" fill="#cf0a2c" opacity="0.85" transform="rotate(135 6 6)"/>`,
        linksys:  `<path d="M3 2 L3 10 L9.5 10 L9.5 8.5 L4.5 8.5 L4.5 2 Z" fill="#0082cb"/>`,
        meraki:   `<path d="M1.5 9.5 L3.5 3.5 L6 7.5 L8.5 3.5 L10.5 9.5" fill="none" stroke="#00a651" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>`,
        mikrotik: `<circle cx="6" cy="6" r="1.5" fill="#4d84b4"/>
                   <circle cx="2.5" cy="3" r="1.2" fill="#4d84b4"/>
                   <circle cx="9.5" cy="3" r="1.2" fill="#4d84b4"/>
                   <circle cx="2.5" cy="9" r="1.2" fill="#4d84b4"/>
                   <circle cx="9.5" cy="9" r="1.2" fill="#4d84b4"/>
                   <line x1="3.5" y1="3.8" x2="5" y2="5" stroke="#4d84b4" stroke-width="1"/>
                   <line x1="8.5" y1="3.8" x2="7" y2="5" stroke="#4d84b4" stroke-width="1"/>
                   <line x1="3.5" y1="8.2" x2="5" y2="7" stroke="#4d84b4" stroke-width="1"/>
                   <line x1="8.5" y1="8.2" x2="7" y2="7" stroke="#4d84b4" stroke-width="1"/>`,
        paloalto: `<rect x="1.5" y="1.5" width="9" height="9" rx="1.5" fill="none" stroke="#fa582d" stroke-width="1.5"/>
                   <line x1="4.5" y1="1.5" x2="4.5" y2="10.5" stroke="#fa582d" stroke-width="1.5"/>
                   <line x1="7.5" y1="1.5" x2="7.5" y2="10.5" stroke="#fa582d" stroke-width="1.5"/>
                   <line x1="1.5" y1="4.5" x2="10.5" y2="4.5" stroke="#fa582d" stroke-width="1.5"/>
                   <line x1="1.5" y1="7.5" x2="10.5" y2="7.5" stroke="#fa582d" stroke-width="1.5"/>`,
        buffalo:  `<rect x="2" y="2" width="8" height="3.5" rx="1" fill="#003087"/>
                   <circle cx="5.5" cy="3.75" r="1.3" fill="#1a5fb4"/>
                   <circle cx="5.5" cy="3.75" r="0.5" fill="#003087"/>
                   <rect x="2" y="6.5" width="8" height="3.5" rx="1" fill="#003087"/>
                   <circle cx="5.5" cy="8.25" r="1.3" fill="#1a5fb4"/>
                   <circle cx="5.5" cy="8.25" r="0.5" fill="#003087"/>`,
        qnap:     `<rect x="2.5" y="1.5" width="7" height="9" rx="1" fill="none" stroke="#00b388" stroke-width="1.5"/>
                   <rect x="3.5" y="3" width="5" height="1.5" rx="0.5" fill="#00b388"/>
                   <rect x="3.5" y="5.5" width="5" height="1.5" rx="0.5" fill="#00b388"/>
                   <rect x="3.5" y="8" width="5" height="1.5" rx="0.5" fill="#00b388"/>`
      };

      // msf console color tokens (rex-text substitute_colors), longest-first
      const TOKEN_RE = /%(bgblu|bgyel|bggrn|bgmag|bgblk|bgred|bgcyn|bgwhi|dred|dgrn|dblu|dyel|dcya|dwhi|dmag|cya|red|grn|blu|yel|whi|mag|blk|und|bld|clr)/g;

      // Renders a raw console line (which may contain %grn/%clr/... tokens)
      // as HTML with color spans, mirroring how the terminal substitutes
      // them: %clr resets everything, %bld/%und accumulate, and color /
      // background tokens replace the previous one of their kind.
      function renderConsoleLine(line) {
        let out = '', last = 0;
        let color = null, bg = null;
        const mods = [];
        const flush = (from, to) => {
          if (to <= from) return;
          const cls = [];
          if (color) cls.push(color);
          if (bg) cls.push(bg);
          cls.push(...mods);
          const seg = esc(line.slice(from, to));
          out += cls.length ? `<span class="${cls.join(' ')}">${seg}</span>` : seg;
        };
        let m;
        TOKEN_RE.lastIndex = 0;
        while ((m = TOKEN_RE.exec(line)) !== null) {
          flush(last, m.index);
          last = m.index + m[0].length;
          const tk = m[1];
          if (tk === 'clr') {
            color = null; bg = null; mods.length = 0;
          } else if (tk === 'bld') {
            if (!mods.includes('tk-bld')) mods.push('tk-bld');
          } else if (tk === 'und') {
            if (!mods.includes('tk-und')) mods.push('tk-und');
          } else if (tk.startsWith('bg')) {
            bg = 'tk-' + tk;
          } else {
            color = 'tk-' + tk;
          }
        }
        flush(last, line.length);
        return out;
      }

      function ansiStrip(s) {
        return String(s).replace(/\u001b\[[0-9;]*[A-Za-z]/g, '');
      }

      // console output and commands can contain markup-significant chars
      function esc(s) {
        return ansiStrip(String(s))
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;');
      }

      function getOsKey(node) {
        if (Object.prototype.hasOwnProperty.call(nodeOsOverride, node.id)) {
          return nodeOsOverride[node.id] || null;
        }
        const os = (node.os_name || node.os_family || '').toLowerCase();
        if (os.includes('windows')) return 'windows';
        if (os.includes('ubuntu')) return 'ubuntu';
        if (os.includes('debian')) return 'debian';
        if (os.includes('red hat') || os.includes('redhat') || os.includes('rhel') || os.includes('centos') || os.includes('fedora')) return 'redhat';
        if (os.includes('vmware') || os.includes('esxi') || os.includes('vsphere') || os.includes('esx')) return 'vmware';
        if (os.includes('android')) return 'android';
        if (os.includes('iphone') || os.includes('ipad') || os.includes('ipados')) return 'ios';
        if (os.includes('freebsd') || os.includes('openbsd') || os.includes('netbsd') || os.includes('dragonfly') || (os.includes('bsd') && !os.includes('ubiquiti'))) return 'bsd';
        if (os.includes('mac') || os.includes('osx') || os.includes('darwin')) return 'macos';
        if (os.includes('meraki')) return 'meraki';
        if (os.includes('cisco') || os.includes('ios xe') || os.includes('ios xr') || os.includes('nx-os') || os.includes('nxos')) return 'cisco';
        if (os.includes('juniper') || os.includes('junos')) return 'juniper';
        if (os.includes('arista') || os.includes(' eos ') || os.startsWith('eos ')) return 'arista';
        if (os.includes('fortinet') || os.includes('fortigate') || os.includes('fortios')) return 'fortinet';
        if (os.includes('aruba') || os.includes('arubaos')) return 'aruba';
        if (os.includes('ubiquiti') || os.includes('unifi') || os.includes('edgeos') || os.includes('edgeswitch')) return 'ubiquiti';
        if (os.includes('huawei') || os.includes('vrp') || os.includes('harmonyos')) return 'huawei';
        if (os.includes('palo alto') || os.includes('pan-os') || os.includes('panos')) return 'paloalto';
        if (os.includes('mikrotik') || os.includes('routeros') || os.includes('routerboard')) return 'mikrotik';
        if (os.includes('netgear') || os.includes('prosafe')) return 'netgear';
        if (os.includes('asuswrt') || (os.includes('asus') && !os.includes('linux'))) return 'asus';
        if (os.includes('tp-link') || os.includes('tplink') || os.includes('tl-')) return 'tplink';
        if (os.includes('linksys') || os.includes('velop')) return 'linksys';
        if (os.includes('eero')) return 'eero';
        if (os.includes('synology') || os.includes('dsm') || os.includes('diskstation')) return 'synology';
        if (os.includes('qnap') || os.includes('qts')) return 'qnap';
        if (os.includes('buffalo') || os.includes('linkstation') || os.includes('terastation')) return 'buffalo';
        if (os.includes('ios') && !os.includes('cisco')) return 'ios';
        if (os.includes('linux') || os.includes('unix')) return 'linux';
        return null;
      }

      function getNodeColor(d) {
        if (nodeColorOverride[d.id]) return nodeColorOverride[d.id];
        if (d.device_type === 'msf') return NODE_COLORS.msf;
        if (d.compromised) return NODE_COLORS.compromised;
        if (d.ever_compromised) return NODE_COLORS.ever_compromised;
        return NODE_COLORS.default;
      }

      function getNodeRadius(d) {
        return d.device_type === 'msf' ? 28 : 22;
      }

      const container = document.getElementById('graph-container');
      const svgEl = document.getElementById('svg');
      const W = container.clientWidth;
      const H = container.clientHeight;

      const svg = d3.select(svgEl).attr('width', W).attr('height', H);

      const defs = svg.append('defs');

      Object.entries(ICON_PATHS).forEach(([type, pathData]) => {
        defs.append('symbol')
          .attr('id', `icon-${type}`)
          .attr('viewBox', '0 0 24 24')
          .html(pathData);
      });

      defs.append('symbol')
        .attr('id', 'icon-msf')
        .attr('viewBox', '0 0 135.47 135.47')
        .html(`<g transform="matrix(1.0444 0 0 1.0444 -3.204 -171.71)">
          <path d="m23.221 176.09v66.222c0 9.4651 9.3645 22.539 18.943 28.972l26.082 17.517 25.813-17.517c9.5475-6.4791 18.943-19.507 18.943-28.972v-66.222c-29.665-8.7742-59.61-8.1596-89.78 0z" fill="#265ab1"/>
          <path d="m29.924 186.24v55.775c0 7.972 10.945 19.391 15.955 24.402v-56.446l14.748 13.274v23.597h14.212v-23.597l14.748-13.274v56.446c5.0103-5.0103 15.955-16.43 15.955-24.402v-55.775h-15.151l-22.658 21.586-22.659-21.586z" opacity=".3"/>
          <path d="m29.924 183.6v55.775c0 7.972 10.945 19.391 15.955 24.402v-56.446l14.748 13.274v23.597h14.212v-23.597l14.748-13.274v56.446c5.0103-5.0103 15.955-16.43 15.955-24.402v-55.775h-15.151l-22.658 21.586-22.659-21.586z" fill="#fff"/>
          <path transform="matrix(.26458 0 0 .26458 0 161.53)" d="m256.72 31.008c-56.563 0.29037-113.37 8.5802-170.38 24v10c114.03-30.84 227.21-33.163 339.33 0v-10c-56.06-16.581-112.38-24.29-168.95-24z" fill="#fff" opacity=".2"/>
          <path transform="matrix(.26458 0 0 .26458 0 161.53)" d="m86.336 295.29v10c0 35.774 35.393 85.186 71.596 109.5l98.576 66.205 97.561-66.205c36.085-24.488 71.596-73.726 71.596-109.5v-10c0 35.774-35.511 85.012-71.596 109.5l-97.561 66.205-98.576-66.205c-36.202-24.314-71.596-73.726-71.596-109.5z" opacity=".3"/>
          <path d="M67.923 169.74c-0.01826 1e-4 -0.03652 4.2e-4 -0.05478 5.2e-4v119.06l25.812-17.517c9.5475-6.4791 18.943-19.506 18.943-28.971v-66.222c-14.832-4.3871-29.735-6.4268-44.701-6.35z" opacity=".2"/>
        </g>`);

      Object.entries(OS_ICONS).forEach(([osKey, pathData]) => {
        defs.append('symbol')
          .attr('id', `os-${osKey}`)
          .attr('viewBox', '0 0 12 12')
          .html(pathData);
      });

      const zoom = d3.zoom()
        .scaleExtent([0.05, 8])
        .on('zoom', (event) => g.attr('transform', event.transform));

      svg.call(zoom);

      svg.on('click', () => {
        clearSelection();
        document.getElementById('type-popup').style.display = 'none';
      });

      const g = svg.append('g');

      function computeDepths(nodes, links) {
        const adj = {};
        links.forEach(l => {
          const s = typeof l.source === 'object' ? l.source.id : l.source;
          const t = typeof l.target === 'object' ? l.target.id : l.target;
          (adj[s] = adj[s] || []).push(t);
          (adj[t] = adj[t] || []).push(s);
        });
        const depth = { '__msf__': 0 };
        const queue = ['__msf__'];
        while (queue.length) {
          const cur = queue.shift();
          for (const nb of (adj[cur] || [])) {
            if (depth[nb] === undefined) { depth[nb] = depth[cur] + 1; queue.push(nb); }
          }
        }
        nodes.forEach(n => { if (depth[n.id] === undefined) depth[n.id] = 1; });
        return depth;
      }

      // Assign each depth level to one or more visual rows, wrapping when the
      // level has too many nodes to fit at a comfortable spacing.  When
      // positionAll is true (first paint), every unpinned node is teleported to
      // its target; otherwise only nodes that lack a position (brand new ones)
      // get teleported so live updates never yank existing nodes around.
      function applyLayerTargets(nodes, depth, canvasW, canvasH, positionAll) {
        const byDepth = {};
        nodes.forEach(n => {
          n._depth = depth[n.id] !== undefined ? depth[n.id] : 1;
          (byDepth[n._depth] = byDepth[n._depth] || []).push(n);
        });

        const isLR = layoutDirection === 'left-right';
        const spreadSize = isLR ? canvasH : canvasW;
        const depthSize  = isLR ? canvasW : canvasH;

        const minSpacing = 100;
        const maxPerLayer = maxPerRowOverride !== null
          ? Math.max(1, maxPerRowOverride)
          : Math.max(5, Math.floor(spreadSize / minSpacing));

        let totalVisualLayers = 0;
        const depthStartLayer = {};
        const depthKeys = Object.keys(byDepth).map(Number).sort((a, b) => a - b);
        depthKeys.forEach(d => {
          depthStartLayer[d] = totalVisualLayers;
          totalVisualLayers += Math.ceil(byDepth[d].length / maxPerLayer);
        });

        const layerSpacing = Math.min(depthSize / (totalVisualLayers + 1), 140);

        depthKeys.forEach(d => {
          const lvl = byDepth[d];
          lvl.forEach((node, i) => {
            const subLayer   = Math.floor(i / maxPerLayer);
            const posInLayer = i % maxPerLayer;
            const layerSize  = Math.min(maxPerLayer, lvl.length - subLayer * maxPerLayer);
            const spreadPos  = spreadSize * (posInLayer + 1) / (layerSize + 1);
            const depthPos   = (depthStartLayer[d] + subLayer + 0.5) * layerSpacing;
            node._xt = isLR ? depthPos  : spreadPos;
            node._yt = isLR ? spreadPos : depthPos;
            const teleport = positionAll || node.x === undefined || node.x === null;
            if (teleport && (node.fx === undefined || node.fx === null)) { node.x = node._xt; node.vx = 0; }
            if (teleport && (node.fy === undefined || node.fy === null)) { node.y = node._yt; node.vy = 0; }
          });
        });

        return layerSpacing;
      }

      const simulation = d3.forceSimulation(simNodes)
        .force('link', d3.forceLink(simLinks).id(d => d.id).strength(0))
        .force('y', d3.forceY(d => d._yt).strength(1.0))
        .force('x', d3.forceX(d => d._xt).strength(1.0))
        .force('collision', d3.forceCollide().radius(d => getNodeRadius(d) + 10))
        .alphaDecay(0.08);

      function rebindSimForces() {
        // forceX/forceY cache targets in an internal array on initialize() and do
        // NOT re-read the accessor on each tick, so re-register on every change.
        simulation.nodes(simNodes);
        simulation.force('link', d3.forceLink(simLinks).id(d => d.id).strength(0));
        simulation.force('x', d3.forceX(d => d._xt).strength(1.0));
        simulation.force('y', d3.forceY(d => d._yt).strength(1.0));
      }

      // Two persistent layers (links below nodes) so live re-joins always target
      // the right group.
      const linksGroup = g.append('g');
      const nodesGroup = g.append('g');

      // Seed selections bound to (initially empty) data so renderPositions and
      // every listener below survive across live re-joins.
      linkSel = linksGroup.selectAll('.link')
        .data(simLinks, linkKey)
        .enter()
        .append('path')
        .attr('class', 'link');

      nodeGroup = nodesGroup.selectAll('.node-group')
        .data(simNodes, d => d.id)
        .enter()
        .append('g')
        .attr('class', 'node-group');

      function linkKey(l) {
        const s = typeof l.source === 'object' ? l.source.id : l.source;
        const t = typeof l.target === 'object' ? l.target.id : l.target;
        return `${s}>${t}`;
      }

      const dragBehavior = d3.drag()
        .on('start', (event, d) => {
          if (!event.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x; d.fy = d.y;
        })
        .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
        .on('end', (event, d) => {
          if (!event.active) simulation.alphaTarget(0);
          // Keep fx/fy set so the node stays pinned where the user dropped it.
        });

      const tooltip = document.getElementById('tooltip');

      function enterNode(enterSel) {
        const grp = enterSel.append('g')
          .attr('class', 'node-group')
          .attr('data-id', d => d.id)
          .style('opacity', 0)
          .call(dragBehavior);

        grp.append('circle')
          .attr('class', 'node-circle')
          .attr('r', d => getNodeRadius(d))
          .attr('fill', d => d.device_type === 'msf' ? 'transparent' : getNodeColor(d))
          .style('stroke', d => d.device_type === 'msf' ? 'none' : (d.compromised ? '#f85149' : null))
          .attr('stroke-width', 2);

        grp.append('use')
          .attr('class', 'device-icon')
          .attr('href', d => `#icon-${d.device_type || 'generic'}`)
          .attr('x', d => d.device_type === 'msf' ? -getNodeRadius(d) : -getNodeRadius(d) * 0.55)
          .attr('y', d => d.device_type === 'msf' ? -getNodeRadius(d) : -getNodeRadius(d) * 0.55)
          .attr('width', d => d.device_type === 'msf' ? getNodeRadius(d) * 2 : getNodeRadius(d) * 1.1)
          .attr('height', d => d.device_type === 'msf' ? getNodeRadius(d) * 2 : getNodeRadius(d) * 1.1)
          .attr('color', 'rgba(255,255,255,0.9)')
          .style('pointer-events', 'none');

        grp.each(function(d) {
          const osKey = getOsKey(d);
          if (!osKey) return;
          d3.select(this).append('use')
            .attr('class', 'os-icon')
            .attr('href', `#os-${osKey}`)
            .attr('x', getNodeRadius(d) - 8)
            .attr('y', -(getNodeRadius(d) + 2))
            .attr('width', 20)
            .attr('height', 20);
        });

        grp.append('text')
          .attr('class', 'node-label')
          .attr('dy', d => getNodeRadius(d) + 14)
          .text(d => d.label.length > 20 ? d.label.substring(0, 18) + '...' : d.label);

        grp
          .on('mouseenter', (event, d) => {
            tooltip.style.display = 'block';
            tooltip.innerHTML = `<strong>${d.label}</strong><br>${d.address}` +
              (d.os_name ? `<br><span class="session-meta">${d.os_name}${d.os_flavor ? ' ' + d.os_flavor : ''}</span>` : '');
          })
          .on('mousemove', (event) => {
            tooltip.style.left = (event.clientX + 14) + 'px';
            tooltip.style.top = (event.clientY - 10) + 'px';
          })
          .on('mouseleave', () => { tooltip.style.display = 'none'; })
          .on('click', (event, d) => {
            event.stopPropagation();
            document.getElementById('type-popup').style.display = 'none';
            selectNode(d);
          })
          .on('contextmenu', (event, d) => {
            event.preventDefault();
            event.stopPropagation();
            showTypePopup(event, d);
          });

        return grp;
      }

      function updateNodeAppearance(sel) {
        sel.select('circle.node-circle')
          .attr('r', d => getNodeRadius(d))
          .attr('fill', d => d.device_type === 'msf' ? 'transparent' : getNodeColor(d))
          .style('stroke', d => d.device_type === 'msf' ? 'none' : (d.compromised ? '#f85149' : null))
          .attr('stroke-width', 2);

        sel.select('use.device-icon')
          .attr('href', d => `#icon-${d.device_type || 'generic'}`)
          .attr('x', d => d.device_type === 'msf' ? -getNodeRadius(d) : -getNodeRadius(d) * 0.55)
          .attr('y', d => d.device_type === 'msf' ? -getNodeRadius(d) : -getNodeRadius(d) * 0.55)
          .attr('width', d => d.device_type === 'msf' ? getNodeRadius(d) * 2 : getNodeRadius(d) * 1.1)
          .attr('height', d => d.device_type === 'msf' ? getNodeRadius(d) * 2 : getNodeRadius(d) * 1.1);

        sel.each(function(d) {
          const el = d3.select(this);
          el.select('use.os-icon').remove();
          const osKey = getOsKey(d);
          if (osKey) {
            el.append('use')
              .attr('class', 'os-icon')
              .attr('href', `#os-${osKey}`)
              .attr('x', getNodeRadius(d) - 8)
              .attr('y', -(getNodeRadius(d) + 2))
              .attr('width', 20)
              .attr('height', 20);
          }
          el.select('text.node-label')
            .attr('dy', d2 => getNodeRadius(d2) + 14)
            .text(d2 => d2.label.length > 20 ? d2.label.substring(0, 18) + '...' : d2.label);
        });
      }

      // Full re-join of nodes and links against the current simNodes/simLinks.
      function rejoin() {
        const linkJoin = linksGroup.selectAll('.link')
          .data(simLinks, linkKey);
        linkJoin.exit()
          .transition().duration(300).style('opacity', 0).remove();
        linkSel = linkJoin.enter()
          .append('path')
          .attr('class', 'link')
          .style('opacity', 0)
          .merge(linkJoin);
        linkSel.transition().duration(400).style('opacity', null);

        const nodeJoin = nodesGroup.selectAll('.node-group')
          .data(simNodes, d => d.id);
        nodeJoin.exit()
          .transition().duration(300).style('opacity', 0).remove();
        nodeGroup = enterNode(nodeJoin.enter()).merge(nodeJoin);
        nodeGroup.transition().duration(600).style('opacity', null);
        updateNodeAppearance(nodeGroup);

        // Live-update eye candy: pulse brand-new nodes, flash nodes that just
        // picked up their first active session.
        nodeGroup.each(function(d) {
          const el = d3.select(this);
          if (d._justAdded) {
            d._justAdded = false;
            el.classed('just-added', true);
            setTimeout(() => el.classed('just-added', false), 6000);
          }
          if (d._flashComp) {
            d._flashComp = false;
            el.classed('flash-comp', true);
            setTimeout(() => el.classed('flash-comp', false), 4000);
          }
        });
      }

      function renderPositions() {
        linkSel.attr('d', d => {
          const sx = d.source.x, sy = d.source.y;
          const tx = d.target.x, ty = d.target.y;
          const cy = (sy + ty) / 2;
          return `M ${sx} ${sy} C ${sx} ${cy}, ${tx} ${cy}, ${tx} ${ty}`;
        });
        nodeGroup.attr('transform', d => `translate(${d.x},${d.y})`);
      }

      simulation.on('tick', renderPositions);

      // Freeze every node where it currently sits once the running animation
      // quiesces (initial layout, arriving nodes, a finished drag).  Pinned
      // nodes are ignored by all forces, so later snapshots can only fill
      // empty space around them - a placed host never moves again.
      function pinAllNodes() {
        simNodes.forEach(n => {
          if (n.x === undefined || n.x === null) return;
          n.fx = n.x;
          n.fy = n.y;
        });
      }
      simulation.on('end', pinAllNodes);

      // ------------------------------------------------------------------
      // Live updates: merge a fresh graph snapshot into the running sim,
      // preserving node positions, pins, and user overrides.
      // ------------------------------------------------------------------
      function applyGraph(payload) {
        if (!payload || !Array.isArray(payload.nodes)) return;
        const raw = JSON.stringify(payload);
        if (raw === lastRaw) return;
        lastRaw = raw;

        const incoming = payload.nodes;
        const incomingLinks = (payload.links || []).map(l => ({ source: l.source, target: l.target }));
        const prev = new Map(simNodes.map(n => [n.id, n]));

        const next = incoming.map(node => {
          const n = Object.assign({}, node);
          const old = prev.get(node.id);
          if (old) {
            // Keep the exact rendered position and pin it: once a host is on
            // screen, no later update - new layer math, new neighbors,
            // collision pushes - may move it.  Only Reset Layout or the user
            // dragging it ever repositions a placed node.
            n.x = old.x; n.y = old.y;
            n.vx = 0; n.vy = 0;
            n.fx = (old.fx !== undefined && old.fx !== null) ? old.fx : old.x;
            n.fy = (old.fy !== undefined && old.fy !== null) ? old.fy : old.y;
            if (!old.compromised && n.compromised && n.device_type !== 'msf') n._flashComp = true;
          } else if (!firstLoad) {
            // brand new node: spawn near its parent hop (or MSF) and glide in
            n._justAdded = true;
            const link = incomingLinks.find(l => l.target === node.id);
            const parentId = link ? link.source : '__msf__';
            const parent = prev.get(parentId) || prev.get('__msf__');
            const cx = (parent && parent.x !== undefined) ? parent.x : W / 2;
            const cy = (parent && parent.y !== undefined) ? parent.y : H / 2;
            const ang = Math.random() * 2 * Math.PI;
            const rad = 60 + Math.random() * 70;
            n.x = cx + Math.cos(ang) * rad;
            n.y = cy + Math.sin(ang) * rad;
          }
          // re-apply local cosmetic overrides chosen via the right-click popup
          if (nodeTypeOverride[n.id]) n.device_type = nodeTypeOverride[n.id];
          return n;
        });

        simNodes = next;
        simLinks = incomingLinks;
        nodeById = Object.fromEntries(simNodes.map(n => [n.id, n]));
        nodeDepth = computeDepths(simNodes, simLinks);
        applyLayerTargets(simNodes, nodeDepth, container.clientWidth, container.clientHeight, firstLoad);
        rebindSimForces();
        rejoin();
        renderPositions();
        // only the brand-new (unpinned) nodes animate; when the sim
        // quiesces, simulation 'end' pins them alongside everything else
        if (physicsRunning) {
          simulation.alpha(firstLoad ? 0.6 : 0.35).restart();
        } else {
          pinAllNodes();
        }

        // keep open sidebar / path highlight pointing at fresh data
        if (selectedNodeId !== null) {
          const sel = simNodes.find(n => n.id === selectedNodeId);
          if (sel) selectNode(sel); else clearSelection();
        }
        populateFilterOpts();
        updateStatus(payload);
        firstLoad = false;
      }

      function updateStatus(payload) {
        const meta = payload.meta || {};
        const c = meta.counts || {};
        const bits = [];
        if (c.hosts !== undefined) bits.push(`${c.hosts} hosts`);
        if (c.sessions !== undefined) bits.push(`${c.sessions} sessions`);
        if (c.vulns !== undefined) bits.push(`${c.vulns} vulns`);
        if (c.creds !== undefined) bits.push(`${c.creds} creds`);
        document.getElementById('live-counts').textContent =
          meta.workspace ? `${bits.join(' - ')} (${meta.workspace})` : bits.join(' - ');
        document.getElementById('live-updated').textContent = new Date().toLocaleTimeString();
        document.getElementById('live-clients').textContent =
          meta.clients !== undefined ? `${meta.clients} viewer${meta.clients === 1 ? '' : 's'}` : '';
        document.getElementById('nodb-banner').style.display = meta.db_active === false ? 'block' : 'none';
        const msf = (payload.nodes || []).find(n => n.id === '__msf__');
        if (msf) updateConsolePanel(msf);
      }

      // Bottom console strip: last command preview in the header, full tail
      // in the expandable body.  Lives outside the sidebar so it stays
      // visible while inspecting any node.
      function updateConsolePanel(msf) {
        const tail = msf.console_tail || [];
        const preview = document.getElementById('console-preview');
        preview.textContent = msf.last_command
          ? `> ${msf.last_command}`
          : (tail.length ? tail[tail.length - 1] : 'no console activity yet');

        const body = document.getElementById('console-body');
        if (!tail.length) {
          body.textContent = '(no console activity yet)';
          return;
        }
        const atBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 24;
        body.innerHTML = tail.map(l =>
          l.startsWith('> ')
            ? `<div class="console-line cmd">${renderConsoleLine(l)}</div>`
            : `<div class="console-line">${renderConsoleLine(l)}</div>`
        ).join('');
        // follow the newest line unless the operator scrolled up to read
        if (atBottom) body.scrollTop = body.scrollHeight;
      }

      window.toggleConsolePanel = function() {
        const panel = document.getElementById('console-panel');
        const collapsed = panel.classList.toggle('collapsed');
        const arrow = document.getElementById('console-toggle');
        arrow.innerHTML = collapsed ? '&#x25b2;' : '&#x25bc;';
        if (!collapsed) {
          const body = document.getElementById('console-body');
          body.scrollTop = body.scrollHeight;
        }
      };
      // ------------------------------------------------------------------
      // Selection / path highlight / sidebar (unchanged behavior from the
      // snapshot version, but re-runs against fresh data after each update)
      // ------------------------------------------------------------------
      function buildAdjacency() {
        const adj = {};
        simLinks.forEach(l => {
          const s = l.source.id || l.source;
          const t = l.target.id || l.target;
          (adj[s] = adj[s] || []).push(t);
          (adj[t] = adj[t] || []).push(s);
        });
        return adj;
      }

      function bfsPath(startId, endId, adj) {
        if (startId === endId) return new Set([startId]);
        const visited = new Set([startId]);
        const prev = {};
        const queue = [startId];
        while (queue.length) {
          const cur = queue.shift();
          for (const nb of (adj[cur] || [])) {
            if (!visited.has(nb)) {
              visited.add(nb);
              prev[nb] = cur;
              if (nb === endId) {
                const path = new Set();
                let n = endId;
                while (n !== undefined) { path.add(n); n = prev[n]; }
                return path;
              }
              queue.push(nb);
            }
          }
        }
        return new Set([startId]);
      }

      function selectNode(d) {
        selectedNodeId = d.id;
        const adj = buildAdjacency();
        const pathSet = bfsPath(d.id, '__msf__', adj);

        linkSel
          .classed('highlighted', l => {
            const s = l.source.id || l.source;
            const t = l.target.id || l.target;
            return pathSet.has(s) && pathSet.has(t);
          })
          .classed('dimmed', l => {
            const s = l.source.id || l.source;
            const t = l.target.id || l.target;
            return !(pathSet.has(s) && pathSet.has(t));
          });

        nodeGroup.classed('dimmed', nd => !pathSet.has(nd.id));
        nodeGroup.classed('selected', nd => nd.id === d.id);

        document.getElementById('btn-deselect').style.display = '';
        showSidebar(d, [...pathSet]);
      }

      function clearSelection() {
        selectedNodeId = null;
        if (linkSel) linkSel.classed('highlighted', false).classed('dimmed', false);
        if (nodeGroup) nodeGroup.classed('dimmed', false).classed('selected', false);
        document.getElementById('btn-deselect').style.display = 'none';
        hideSidebar();
      }

      function showSidebar(d, pathNodeIds) {
        const sidebar = document.getElementById('sidebar');
        sidebar.classList.remove('hidden');
        document.getElementById('sidebar-title').textContent = d.label;

        const osStr = [d.os_name, d.os_flavor, d.os_sp].filter(Boolean).join(' ');
        const osKey = getOsKey(d);
        const osIconHtml = osKey ? `<svg width="16" height="16" viewBox="0 0 12 12" style="vertical-align:middle;margin-right:5px;flex-shrink:0;display:inline-block"><use href="#os-${osKey}" width="12" height="12"/></svg>` : '';
        const sessionsBadges = [...d.sessions].sort((a, b) => b.active - a.active).map(s =>
          `<div class="session-entry ${s.active ? 'session-active' : 'session-closed'}"
                data-exploit="${s.via_exploit}" data-payload="${s.via_payload}"
                data-lhost="${s.lhost}" data-lport="${s.lport}" data-rhost="${d.address}" data-rport="${s.rport}">
            <div class="session-header">
              <div>
                <span class="badge ${s.active ? 'badge-compromised' : 'badge-closed'}">${s.active ? 'ACTIVE' : 'CLOSED'}</span>
                <strong>#${s.id}</strong> ${s.type}
              </div>
              <button class="copy-session-btn" onclick="copySessionSetup(this)" title="Copy recreation commands">&#x2398;</button>
            </div>
            <span class="session-meta">${s.via_exploit || 'unknown exploit'}</span><br>
            ${s.via_payload ? `<span class="session-meta">${s.via_payload}</span><br>` : ''}
            <span class="session-meta">Opened: ${s.opened_at || 'unknown'}</span>
            ${!s.active ? `<br><span class="session-meta">Closed: ${s.closed_at}</span>` : ''}
          </div>`
        ).join('');

        const servicesBadges = d.services.slice(0, 30).map(s =>
          `<span class="badge badge-port">${s.port}/${s.proto}${s.name ? ' ' + s.name : ''}</span>`
        ).join('');

        let routeHtml = '';
        if (d.device_type !== 'msf' && pathNodeIds && pathNodeIds.length > 1) {
          const hops = pathNodeIds.map(id => {
            if (id === '__msf__') return { label: 'MSF', rtt: null };
            const n = nodeById[id];
            return { label: n ? (n.address || n.label) : id, rtt: n ? n.rtt : null };
          });
          const totalRtt = hops.reduce((sum, h) => sum + (h.rtt > 0 ? Number(h.rtt) : 0), 0);
          routeHtml = `<div class="detail-group">
            <div class="detail-label collapsible-label" onclick="toggleSection(this)">
              <span>Route to Host</span>
              <button class="section-toggle">&#x25bc;</button>
            </div>
            <div class="collapsible-body">
              <div class="route-list">
                ${hops.map((h, i) => {
                  const rttStr = h.rtt > 0 ? `<span class="rtt-label">(${Number(h.rtt).toFixed(2)}ms)</span>` : '';
                  const totalStr = i === 0 && totalRtt > 0 ? ` <span class="rtt-label rtt-total">total: ${totalRtt.toFixed(2)}ms</span>` : '';
                  return i === 0
                    ? `<div class="route-entry-first">${h.label}${totalStr}</div>`
                    : `<div class="route-entry-hop">${h.label}${rttStr}</div>`;
                }).join('')}
              </div>
            </div>
          </div>`;
        }

        let html = `
          <div class="detail-group">
            <div class="detail-label">IP Address</div>
            <div class="detail-value">${d.address || '&mdash;'}</div>
          </div>
          ${routeHtml}
          ${d.name ? `<div class="detail-group">
            <div class="detail-label">Hostname</div>
            <div class="detail-value">${d.name}</div>
          </div>` : ''}
          ${d.mac ? `<div class="detail-group">
            <div class="detail-label">MAC Address</div>
            <div class="detail-value">${d.mac}</div>
          </div>` : ''}
          ${osStr ? `<div class="detail-group">
            <div class="detail-label">Operating System</div>
            <div class="detail-value" style="display:flex;align-items:center">${osIconHtml}${osStr}</div>
          </div>` : ''}
          ${d.arch ? `<div class="detail-group">
            <div class="detail-label">Architecture</div>
            <div class="detail-value">${d.arch}</div>
          </div>` : ''}
          ${d.purpose ? `<div class="detail-group">
            <div class="detail-label">Purpose</div>
            <div class="detail-value">${d.purpose}</div>
          </div>` : ''}
          <div class="detail-group">
            <div class="detail-label">Status</div>
            <div class="detail-value">
              ${d.device_type === 'msf' ? '<span class="badge badge-session">MSF FRAMEWORK</span>' :
                d.compromised ? '<span class="badge badge-compromised">ACTIVE SESSION</span>' :
                d.ever_compromised ? '<span class="badge badge-ever-compromised">PREVIOUSLY COMPROMISED</span>' :
                '<span class="badge badge-closed">DISCOVERED</span>'}
            </div>
          </div>`;

        if (d.device_type === 'msf') {
          const jobs = d.jobs || [];
          html += `<div class="detail-group">
            <div class="detail-label">Jobs (${jobs.length})</div>
            ${jobs.length
              ? jobs.map(j => `<div class="job-entry"><span class="job-id">#${j.id}</span> ${esc(j.name)}${j.started ? `<div class="session-meta">started ${j.started}</div>` : ''}</div>`).join('')
              : '<div class="session-meta">no background jobs running</div>'}
          </div>`;
        }

        if (d.sessions && d.sessions.length > 0) {
          const hasActive = d.sessions.some(s => s.active);
          html += `<div class="detail-group">
            <div class="detail-label collapsible-label" onclick="toggleSection(this)">
              <span>Sessions (${d.sessions.length})</span>
              <button class="section-toggle">${hasActive ? '&#x25bc;' : '&#x25ba;'}</button>
            </div>
            <div class="collapsible-body${hasActive ? '' : ' collapsed'}">${sessionsBadges}</div>
          </div>`;
        }

        {
          const modules = [...new Set([
            ...((d.sessions || []).map(s => s.via_exploit)),
            ...(d.event_modules || []),
            ...((d.module_runs || []).map(r => r.module_fullname))
          ].filter(Boolean))].sort();
          if (modules.length > 0) {
            html += `<div class="detail-group">
              <div class="detail-label collapsible-label" onclick="toggleSection(this)">
                <span>Modules Used (${modules.length})</span>
                <button class="section-toggle">&#x25ba;</button>
              </div>
              <div class="collapsible-body collapsed">
                ${modules.map(m => `<div class="module-entry">${m}</div>`).join('')}
              </div>
            </div>`;
          }
        }

        if (d.vulns && d.vulns.length > 0) {
          const vulnHtml = d.vulns.map(v => {
            const refs = (v.refs || []).map(r => `<span class="vuln-ref">${r}</span>`).join('');
            const exploited = v.exploited_at ? `<div class="vuln-exploited">Exploited: ${v.exploited_at}</div>` : '';
            return `<div class="vuln-entry">
              <div class="vuln-name">${v.name}</div>
              ${v.info ? `<div class="vuln-info">${v.info}</div>` : ''}
              ${refs ? `<div class="vuln-refs">${refs}</div>` : ''}
              ${exploited}
            </div>`;
          }).join('');
          html += `<div class="detail-group">
            <div class="detail-label collapsible-label" onclick="toggleSection(this)">
              <span>Vulnerabilities (${d.vulns.length})</span>
              <button class="section-toggle">&#x25ba;</button>
            </div>
            <div class="collapsible-body collapsed">${vulnHtml}</div>
          </div>`;
        }

        if (d.services && d.services.length > 0) {
          html += `<div class="detail-group">
            <div class="detail-label">Services (${d.services.length})</div>
            <div class="services-list">${servicesBadges}</div>
          </div>`;
        }

        if (d.loots && d.loots.length > 0) {
          const lootEntries = d.loots.map(l => {
            const filename = l.name || (l.path || '').split('/').pop() || 'loot';
            const fileUrl = 'file://' + l.path;
            return `<a class="loot-entry" href="${fileUrl}" target="_blank" title="Click to open ${fileUrl}">
              ${l.info ? `<div class="loot-info">${l.info}</div>` : ''}
              ${l.ltype ? `<div class="loot-meta">${l.ltype}</div>` : ''}
              <div class="loot-name">${filename}</div>
            </a>`;
          }).join('');
          html += `<div class="detail-group">
            <div class="detail-label collapsible-label" onclick="toggleSection(this)">
              <span>Loot (${d.loots.length})</span>
              <button class="section-toggle">&#x25ba;</button>
            </div>
            <div class="collapsible-body collapsed">${lootEntries}</div>
          </div>`;
        }

        if (d.creds && d.creds.length > 0) {
          const credEntries = d.creds.map(c => {
            const statusKey = (c.status || '').toLowerCase().replace(/\s+/g, '-');
            const statusBadge = c.status ? `<span class="cred-status cred-status-${statusKey}">${c.status}</span>` : '';
            return `<div class="cred-entry">
              <div class="cred-username">${c.username || '(blank)'}${statusBadge}</div>
              <div class="cred-meta">Type: ${c.type}${c.domain ? ` &bull; Domain: ${c.domain}` : ''}</div>
            </div>`;
          }).join('');
          html += `<div class="detail-group">
            <div class="detail-label collapsible-label" onclick="toggleSection(this)">
              <span>Credentials (${d.creds.length})</span>
              <button class="section-toggle">&#x25ba;</button>
            </div>
            <div class="collapsible-body collapsed">${credEntries}</div>
          </div>`;
        }

        document.getElementById('sidebar-content').innerHTML = html;
      }

      function hideSidebar() {
        document.getElementById('sidebar').classList.add('hidden');
      }

      document.getElementById('sidebar-close').addEventListener('click', () => clearSelection());

      // ------------------------------------------------------------------
      // Right-click type/OS/color popup
      // ------------------------------------------------------------------
      const typeLabels = {
        computer: 'Computer', server: 'Server', router: 'Router',
        switch: 'Switch', firewall: 'Firewall', phone: 'Phone/Mobile',
        printer: 'Printer', msf: 'MSF Framework', generic: 'Generic/Unknown'
      };

      let typePopupNodeId = null;

      function showTypePopup(event, d) {
        typePopupNodeId = d.id;
        const currentType = nodeTypeOverride[d.id] || d.device_type || 'generic';
        const popup = document.getElementById('type-popup');

        document.getElementById('type-opts').innerHTML = DEVICE_TYPES.map(t =>
          `<div class="type-opt ${t === currentType ? 'active' : ''}" onclick="applyTypeChange('${t}')">
            <svg width="18" height="18" viewBox="0 0 24 24" style="flex-shrink:0">
              <use href="#icon-${t}" width="18" height="18" color="currentColor"/>
            </svg>
            ${typeLabels[t] || t}
          </div>`
        ).join('');

        document.getElementById('node-color-picker').value = nodeColorOverride[d.id] || getNodeColor(d);

        const currentOs = Object.prototype.hasOwnProperty.call(nodeOsOverride, d.id)
          ? nodeOsOverride[d.id]
          : getOsKey(d);
        document.getElementById('os-opts').innerHTML = [
          ...OS_CATEGORIES.map((cat, ci) =>
            `<div class="os-cat-header${ci > 0 ? ' os-cat-sep' : ''}" onclick="this.nextElementSibling.classList.toggle('collapsed');this.querySelector('.os-cat-arrow').textContent=this.nextElementSibling.classList.contains('collapsed')?'&#x25b6;':'&#x25bc;'">
              ${cat.name}<span class="os-cat-arrow">&#x25bc;</span>
            </div>
            <div class="os-cat-body">
              ${cat.keys.map(os =>
                `<div class="type-opt ${os === currentOs ? 'active' : ''}" onclick="applyOsChange('${os}')">
                  <svg width="20" height="20" viewBox="0 0 12 12" style="flex-shrink:0"><use href="#os-${os}" width="12" height="12"/></svg>
                  ${osLabels[os]}
                </div>`).join('')}
            </div>`),
          `<div class="popup-divider"></div>`,
          `<div class="type-opt ${'none' === currentOs ? 'active' : ''}" onclick="applyOsChange('none')">
            <span style="width:15px;display:inline-block;flex-shrink:0"></span> None
          </div>`,
          `<div class="type-opt ${currentOs === null && !Object.prototype.hasOwnProperty.call(nodeOsOverride, d.id) ? 'active' : ''}" onclick="applyOsChange('__auto__')">
            <span style="width:15px;display:inline-block;flex-shrink:0"></span> Auto-detect
          </div>`
        ].join('');

        document.getElementById('configure-submenu').style.display = 'none';
        document.getElementById('submenu-arrow').innerHTML = '&#x25b6;';

        popup.style.left = event.clientX + 'px';
        popup.style.top = event.clientY + 'px';
        popup.style.display = 'block';
      }

      window.toggleSubmenu = function(e) {
        e.stopPropagation();
        const sub = document.getElementById('configure-submenu');
        const arrow = document.getElementById('submenu-arrow');
        const opening = sub.style.display !== 'block';
        sub.style.display = opening ? 'block' : 'none';
        arrow.innerHTML = opening ? '&#x25c0;' : '&#x25b6;';
      };

      window.applyTypeChange = function(newType) {
        if (!typePopupNodeId) return;
        nodeTypeOverride[typePopupNodeId] = newType;

        nodeGroup.each(function(d) {
          if (d.id !== typePopupNodeId) return;
          d.device_type = newType;
          updateNodeAppearance(d3.select(this));
        });

        document.getElementById('type-popup').style.display = 'none';
      };

      window.applyOsChange = function(osKey) {
        if (!typePopupNodeId) return;
        if (osKey === '__auto__') {
          delete nodeOsOverride[typePopupNodeId];
        } else {
          nodeOsOverride[typePopupNodeId] = osKey === 'none' ? '' : osKey;
        }
        nodeGroup.each(function(d) {
          if (d.id !== typePopupNodeId) return;
          updateNodeAppearance(d3.select(this));
        });
        document.getElementById('type-popup').style.display = 'none';
      };

      window.copySessionSetup = function(btn) {
        const card = btn.closest('.session-entry');
        const lines = [];
        if (card.dataset.exploit) lines.push(`use ${card.dataset.exploit}`);
        if (card.dataset.payload) lines.push(`set payload ${card.dataset.payload}`);
        if (card.dataset.rhost)   lines.push(`set rhost ${card.dataset.rhost}`);
        if (card.dataset.rport)   lines.push(`set rport ${card.dataset.rport}`);
        if (card.dataset.lhost)   lines.push(`set lhost ${card.dataset.lhost}`);
        if (card.dataset.lport)   lines.push(`set lport ${card.dataset.lport}`);
        navigator.clipboard.writeText(lines.join('\n')).then(() => {
          btn.innerHTML = '&#x2713;';
          setTimeout(() => { btn.innerHTML = '&#x2398;'; }, 1500);
        });
      };

      window.toggleSection = function(header) {
        const body = header.parentElement.querySelector('.collapsible-body');
        const btn = header.querySelector('.section-toggle');
        const collapsed = body.classList.toggle('collapsed');
        btn.innerHTML = collapsed ? '&#x25ba;' : '&#x25bc;';
      };

      // ------------------------------------------------------------------
      // Filters (re-populated on every live update, preserving checked state)
      // ------------------------------------------------------------------
      window.filterModuleList = function(query) {
        const q = query.toLowerCase();
        document.querySelectorAll('#filter-module-opts label').forEach(label => {
          label.style.display = label.textContent.toLowerCase().includes(q) ? '' : 'none';
        });
      };

      window.filterCredList = function(query) {
        const q = query.toLowerCase();
        document.querySelectorAll('#filter-cred-opts label').forEach(label => {
          label.style.display = label.textContent.toLowerCase().includes(q) ? '' : 'none';
        });
      };

      window.toggleFilter = function() {
        const body = document.getElementById('filter-body');
        const arrow = document.getElementById('filter-arrow');
        const opening = body.style.display === 'none' || body.style.display === '';
        body.style.display = opening ? 'block' : 'none';
        arrow.innerHTML = opening ? '&#x25bc;' : '&#x25b2;';
      };

      function applyFilter() {
        const mode = document.querySelector('input[name="filter-mode"]:checked').value;
        const sessionFilters = [...document.querySelectorAll('.filter-session:checked')].map(el => el.value);
        const deviceFilters  = [...document.querySelectorAll('.filter-device:checked')].map(el => el.value);
        const osFilters      = [...document.querySelectorAll('.filter-os:checked')].map(el => el.value);
        const portFilters    = document.getElementById('filter-ports').value
          .split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
        const moduleFilters  = [...document.querySelectorAll('.filter-module:checked')].map(el => el.value);
        const credHasFilter    = document.querySelector('.filter-cred-has:checked') !== null;
        const credFilters      = [...document.querySelectorAll('.filter-cred:checked')].map(el => el.value);
        const credStatusFilters = [...document.querySelectorAll('.filter-cred-status:checked')].map(el => el.value);

        const hasFilter = sessionFilters.length || deviceFilters.length || osFilters.length || portFilters.length || moduleFilters.length || credHasFilter || credFilters.length || credStatusFilters.length;
        const filteredOut = new Set();

        nodeGroup.classed('filter-hidden', false).classed('filter-dimmed', false);

        if (hasFilter) {
          nodeGroup.each(function(d) {
            if (d.device_type === 'msf') return;
            let match = true;
            if (sessionFilters.length) {
              match = sessionFilters.some(f =>
                (f === 'active' && d.compromised) || (f === 'ever' && d.ever_compromised)
              );
            }
            if (match && deviceFilters.length && !deviceFilters.includes(d.device_type)) match = false;
            if (match && osFilters.length) {
              const osKey = getOsKey(d);
              if (!osKey || !osFilters.includes(osKey)) match = false;
            }
            if (match && portFilters.length) {
              const nodePorts = (d.services || []).map(s => s.port);
              if (!portFilters.some(p => nodePorts.includes(p))) match = false;
            }
            if (match && moduleFilters.length) {
              const nodeModules = [
                ...(d.sessions || []).map(s => s.via_exploit),
                ...(d.event_modules || []),
                ...(d.module_runs || []).map(r => r.module_fullname)
              ].filter(Boolean);
              if (!moduleFilters.some(m => nodeModules.includes(m))) match = false;
            }
            if (match && credHasFilter && !(d.creds && d.creds.length > 0)) match = false;
            if (match && credStatusFilters.length) {
              const nodeStatuses = (d.creds || []).map(c => c.status);
              if (!credStatusFilters.some(s => nodeStatuses.includes(s))) match = false;
            }
            if (match && credFilters.length) {
              const nodeUsernames = (d.creds || []).map(c => c.username);
              if (!credFilters.some(u => nodeUsernames.includes(u))) match = false;
            }
            if (!match) {
              filteredOut.add(d.id);
              d3.select(this).classed(mode === 'hide' ? 'filter-hidden' : 'filter-dimmed', true);
            }
          });
        }

        linkSel.classed('filter-hidden', false).classed('filter-dimmed', false);
        if (filteredOut.size) {
          linkSel.each(function(l) {
            const srcId = typeof l.source === 'object' ? l.source.id : l.source;
            const tgtId = typeof l.target === 'object' ? l.target.id : l.target;
            if (filteredOut.has(srcId) || filteredOut.has(tgtId)) {
              d3.select(this).classed(mode === 'hide' ? 'filter-hidden' : 'filter-dimmed', true);
            }
          });
        }

        document.getElementById('filter-toggle').classList.toggle('active', hasFilter);
      }

      function populateFilterOpts() {
        // keep whatever the user has checked across live refreshes
        const checked = {};
        document.querySelectorAll('.filter-device, .filter-os, .filter-module, .filter-cred').forEach(el => {
          if (el.checked) (checked[el.className] = checked[el.className] || new Set()).add(el.value);
        });
        const isChecked = (cls, val) => (checked[cls] || new Set()).has(val);

        const deviceTypes = [...new Set(simNodes.filter(n => n.device_type !== 'msf').map(n => n.device_type))].sort();
        const osKeys = [...new Set(simNodes.map(n => getOsKey(n)).filter(Boolean))].sort();
        const allModules = [...new Set(simNodes.flatMap(n => [
          ...(n.sessions || []).map(s => s.via_exploit),
          ...(n.event_modules || []),
          ...(n.module_runs || []).map(r => r.module_fullname)
        ].filter(Boolean)))].sort();

        const deviceContainer = document.getElementById('filter-device-opts');
        deviceContainer.innerHTML = '';
        deviceTypes.forEach(dt => {
          const label = document.createElement('label');
          label.className = 'filter-opt';
          const cb = `<input type="checkbox" class="filter-device" value="${dt}"${isChecked('filter-device', dt) ? ' checked' : ''}>`;
          label.innerHTML = `${cb} ${typeLabels[dt] || dt}`;
          deviceContainer.appendChild(label);
        });

        const osContainer = document.getElementById('filter-os-opts');
        osContainer.innerHTML = '';
        osKeys.forEach(ok => {
          const label = document.createElement('label');
          label.className = 'filter-opt';
          const cb = `<input type="checkbox" class="filter-os" value="${ok}"${isChecked('filter-os', ok) ? ' checked' : ''}>`;
          label.innerHTML = `${cb} ${osLabels[ok] || ok}`;
          osContainer.appendChild(label);
        });

        const moduleContainer = document.getElementById('filter-module-opts');
        moduleContainer.innerHTML = '';
        allModules.forEach(m => {
          const label = document.createElement('label');
          label.className = 'filter-opt';
          label.style.fontFamily = 'monospace';
          label.style.fontSize = '11px';
          const cb = `<input type="checkbox" class="filter-module" value="${m}"${isChecked('filter-module', m) ? ' checked' : ''}>`;
          label.innerHTML = `${cb} ${m}`;
          moduleContainer.appendChild(label);
        });

        const allUsernames = [...new Set(simNodes.flatMap(n => (n.creds || []).map(c => c.username)).filter(Boolean))].sort();
        const credContainer = document.getElementById('filter-cred-opts');
        credContainer.innerHTML = '';
        allUsernames.forEach(u => {
          const label = document.createElement('label');
          label.className = 'filter-opt';
          label.style.fontFamily = 'monospace';
          label.style.fontSize = '11px';
          const cb = `<input type="checkbox" class="filter-cred" value="${u}"${isChecked('filter-cred', u) ? ' checked' : ''}>`;
          label.innerHTML = `${cb} ${u}`;
          credContainer.appendChild(label);
        });

        filterModuleList(document.getElementById('filter-module-search').value || '');
        filterCredList(document.getElementById('filter-cred-search').value || '');
        applyFilter();
      }

      document.getElementById('filter-body').addEventListener('change', applyFilter);
      document.getElementById('filter-ports').addEventListener('input', applyFilter);

      document.getElementById('btn-filter-clear').addEventListener('click', function() {
        document.querySelectorAll('.filter-session, .filter-device, .filter-os, .filter-module, .filter-cred, .filter-cred-has, .filter-cred-status').forEach(el => el.checked = false);
        document.getElementById('filter-ports').value = '';
        document.getElementById('filter-module-search').value = '';
        filterModuleList('');
        document.getElementById('filter-cred-search').value = '';
        filterCredList('');
        applyFilter();
      });

      window.applyColorChange = function() {
        if (!typePopupNodeId) return;
        const color = document.getElementById('node-color-picker').value;
        nodeColorOverride[typePopupNodeId] = color;
        nodeGroup.each(function(d) {
          if (d.id !== typePopupNodeId) return;
          d3.select(this).select('.node-circle').attr('fill', color);
        });
      };

      window.resetNodeColor = function() {
        if (!typePopupNodeId) return;
        delete nodeColorOverride[typePopupNodeId];
        nodeGroup.each(function(d) {
          if (d.id !== typePopupNodeId) return;
          const defaultColor = getNodeColor(d);
          d3.select(this).select('.node-circle').attr('fill', defaultColor);
          document.getElementById('node-color-picker').value = defaultColor;
        });
      };

      // ------------------------------------------------------------------
      // Layout / configure controls
      // ------------------------------------------------------------------
      let physicsRunning = true;

      function resetLayout() {
        simNodes.forEach(n => { n.fx = null; n.fy = null; });
        applyLayerTargets(simNodes, nodeDepth, container.clientWidth, container.clientHeight, true);
        rebindSimForces();
        renderPositions();
        // explicit user action: re-layout, then re-freeze once it settles
        // (simulation 'end' pins everything when physics is running)
        if (physicsRunning) simulation.alpha(0.5).restart();
        else pinAllNodes();
      }

      window.toggleConfigure = function() {
        const body = document.getElementById('configure-body');
        const arrow = document.getElementById('cfg-arrow');
        const opening = body.style.display === 'none' || body.style.display === '';
        body.style.display = opening ? 'block' : 'none';
        arrow.innerHTML = opening ? '&#x25bc;' : '&#x25b2;';
      };

      document.getElementById('btn-reset').addEventListener('click', () => {
        resetLayout();
        svg.transition().duration(600).call(zoom.transform, d3.zoomIdentity);
      });

      document.getElementById('cfg-physics').addEventListener('change', function() {
        physicsRunning = this.checked;
        physicsRunning ? simulation.restart() : simulation.stop();
      });

      document.getElementById('cfg-nodes-per-row').addEventListener('input', function() {
        const val = parseInt(this.value);
        maxPerRowOverride = (isFinite(val) && val >= 1) ? val : null;
        resetLayout();
      });

      document.querySelectorAll('input[name="layout-dir"]').forEach(radio => {
        radio.addEventListener('change', function() {
          layoutDirection = this.value;
          resetLayout();
        });
      });

      document.getElementById('btn-deselect').addEventListener('click', () => clearSelection());

      document.getElementById('legend-toggle').addEventListener('click', (e) => {
        e.stopPropagation();
        const legend = document.getElementById('legend');
        const collapsed = legend.classList.toggle('collapsed');
        e.currentTarget.innerHTML = collapsed ? '&#x2b;' : '&#x2212;';
        e.currentTarget.title = collapsed ? 'Show legend' : 'Minimize legend';
      });

      document.addEventListener('click', (e) => {
        const popup = document.getElementById('type-popup');
        if (!popup.contains(e.target)) popup.style.display = 'none';
      });

      window.exportImage = function() {
        const svgEl2 = document.getElementById('svg');
        const W2 = svgEl2.clientWidth;
        const H2 = svgEl2.clientHeight;

        const cs = getComputedStyle(document.documentElement);
        const rv = k => cs.getPropertyValue(k).trim();

        const clone = svgEl2.cloneNode(true);
        clone.setAttribute('width', W2);
        clone.setAttribute('height', H2);

        const bgRect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
        bgRect.setAttribute('width', W2);
        bgRect.setAttribute('height', H2);
        bgRect.setAttribute('fill', rv('--bg-canvas'));
        clone.insertBefore(bgRect, clone.firstChild);

        const styleEl = document.createElementNS('http://www.w3.org/2000/svg', 'style');
        styleEl.textContent = `
          .node-label { fill:${rv('--text-muted')}; font-size:11px; text-anchor:middle;
                        font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; pointer-events:none; }
          .link { fill:none; stroke:${rv('--graph-edge')}; stroke-width:1.5; stroke-opacity:0.8; }
          .link.highlighted { stroke:#f85149; stroke-width:3; stroke-opacity:1; }
          .link.dimmed { stroke-opacity:0.15; }
          .node-circle { stroke:${rv('--accent')}; stroke-width:2; }
          .node-group.dimmed { opacity:0.25; }
          .node-group.selected .node-circle { stroke-width:3; }
        `;
        clone.insertBefore(styleEl, clone.firstChild);

        const svgStr = new XMLSerializer().serializeToString(clone);
        const blob = new Blob([svgStr], { type: 'image/svg+xml;charset=utf-8' });
        const url = URL.createObjectURL(blob);

        const img = new Image();
        img.onload = function() {
          const scale = window.devicePixelRatio || 1;
          const canvas = document.createElement('canvas');
          canvas.width = W2 * scale;
          canvas.height = H2 * scale;
          const ctx = canvas.getContext('2d');
          ctx.scale(scale, scale);
          ctx.drawImage(img, 0, 0);
          URL.revokeObjectURL(url);
          const a = document.createElement('a');
          a.download = 'network-graph.png';
          a.href = canvas.toDataURL('image/png');
          a.click();
        };
        img.onerror = function() {
          URL.revokeObjectURL(url);
        };
        img.src = url;
      };

      window.toggleTheme = function() {
        const light = document.body.classList.toggle('light');
        document.getElementById('theme-toggle').innerHTML = light ? '&#x2600;' : '&#x263d;';
        try { localStorage.setItem('msf-graph-theme', light ? 'light' : 'dark'); } catch(e) {}
      };
      (function initTheme() {
        let pref = 'dark';
        try { pref = localStorage.getItem('msf-graph-theme') || 'dark'; } catch(e) {}
        if (pref === 'light') {
          document.body.classList.add('light');
          document.getElementById('theme-toggle').innerHTML = '&#x2600;';
        }
      })();

      window.addEventListener('resize', () => {
        const nW = container.clientWidth;
        const nH = container.clientHeight;
        svg.attr('width', nW).attr('height', nH);
        applyLayerTargets(simNodes, nodeDepth, nW, nH, false);
        rebindSimForces();
        simulation.alpha(0.3).restart();
      });

      // ------------------------------------------------------------------
      // Live connection: websocket first, polling fallback
      // ------------------------------------------------------------------
      let ws = null;
      let wsFails = 0;
      let pollTimer = null;
      const liveDot = document.getElementById('live-dot');
      const liveLabel = document.getElementById('live-label');

      function setLive(mode, text) {
        liveDot.className = 'dot ' + mode;
        liveLabel.className = 'live-label' + (mode === '' ? '' : ' ' + mode);
        liveLabel.textContent = text;
      }

      function enterPolling() {
        setLive('polling', 'POLLING');
        if (pollTimer) return;
        pollTimer = setInterval(() => {
          fetch('/graph.json', { cache: 'no-store' })
            .then(r => r.json())
            .then(p => { setLive('polling', 'POLLING'); applyGraph(p); })
            .catch(() => setLive('off', 'OFFLINE'));
        }, 3000);
      }

      function stopPolling() {
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
      }

      function connectWS() {
        let sock;
        try {
          const proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
          sock = new WebSocket(proto + location.host + '/ws');
        } catch (e) {
          enterPolling();
          return;
        }
        ws = sock;
        sock.onopen = () => {
          wsFails = 0;
          stopPolling();
          setLive('live', 'LIVE');
        };
        sock.onmessage = (ev) => {
          try { applyGraph(JSON.parse(ev.data)); } catch (e) { console.error('bad payload', e); }
        };
        sock.onclose = () => {
          if (ws !== sock) return; // replaced or page going away
          setLive('off', 'RECONNECTING');
          wsFails++;
          if (wsFails >= 3) enterPolling();
          setTimeout(connectWS, Math.min(10000, 500 * Math.pow(2, wsFails)));
        };
        sock.onerror = () => { /* onclose always follows */ };
      }

      // initial paint from a plain fetch, then keep it live over the socket
      fetch('/graph.json', { cache: 'no-store' })
        .then(r => r.json())
        .then(applyGraph)
        .catch(() => { document.getElementById('live-counts').textContent = 'waiting for data...'; });
      connectWS();
    })();
      </script>
    </body>
    </html>
  HTML
end
