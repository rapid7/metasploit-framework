#!/usr/bin/env ruby
# -*- coding: binary -*-

#
# by h00die
#
# Fetches all stable GitLab EE and CE Docker tags newer than the highest version
# already present in version.json, then pulls only the application layer blob
# directly from the Docker Registry API (no Docker daemon required) and streams
# it through gzip+tar to extract the application-HASH.css filename.
#
# Requirements: none beyond Ruby stdlib
#
# Usage:
#   ruby tools/dev/update_gitlab_versions.rb [options]
#

require 'optparse'
require 'net/http'
require 'uri'
require 'json'
require 'set'
require 'zlib'

# -- paths / constants ---------------------------------------------------------

JSON_FILE = File.expand_path('../../data/gitlab_versions.json', __dir__)
REGISTRY = 'https://registry-1.docker.io/v2'.freeze
AUTH_URL = 'https://auth.docker.io/token?service=registry.docker.io'.freeze
MAX_CONCURRENT = 4

EE_TAG_RE = /\A(\d+)\.(\d+)\.(\d+)-ee\.(\d+)\z/
CE_TAG_RE = /\A(\d+)\.(\d+)\.(\d+)-ce\.(\d+)\z/

EDITIONS = [
  {
    repo: 'gitlab/gitlab-ee', tag_re: EE_TAG_RE, label: 'EE',
    version_fn: ->(tag) { tag.sub(/-ee\.\d+\z/, '-ee') }
  },
  {
    repo: 'gitlab/gitlab-ce', tag_re: CE_TAG_RE, label: 'CE',
    version_fn: ->(tag) { tag.sub(/-ce\.\d+\z/, '-ce') }
  }
].freeze

# Prefer Docker v2 manifest types - OCI manifests may use zstd-compressed layers
# which we cannot decompress. Docker v2 layers are always gzip.
MANIFEST_ACCEPT = [
  'application/vnd.docker.distribution.manifest.v2+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.oci.image.manifest.v1+json'
].join(', ').freeze

# -- colours -------------------------------------------------------------------

class String
  def red
    "\e[1;31;40m#{self}\e[0m"
  end

  def yellow
    "\e[1;33;40m#{self}\e[0m"
  end

  def green
    "\e[1;32;40m#{self}\e[0m"
  end

  def cyan
    "\e[1;36;40m#{self}\e[0m"
  end
end

# -- helpers -------------------------------------------------------------------

def tag_semver(tag, re)
  m = re.match(tag)
  return nil unless m

  [m[1].to_i, m[2].to_i, m[3].to_i]
end

def parse_semver(str)
  m = str.match(/\A(\d+)\.(\d+)\.(\d+)/)
  m ? [m[1].to_i, m[2].to_i, m[3].to_i] : nil
end

def http_get(url)
  uri = URI(url)
  Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https',
                                      open_timeout: 15, read_timeout: 30) do |http|
    http.request(Net::HTTP::Get.new(uri))
  end
end

# -- Docker Hub tag enumeration -------------------------------------------------

def fetch_all_tags(repo)
  tags = []
  url = "https://hub.docker.com/v2/repositories/#{repo}/tags?page_size=100&ordering=last_updated"

  loop do
    resp = http_get(url)
    unless resp.is_a?(Net::HTTPSuccess)
      warn "  Docker Hub request failed (#{resp.code}): #{url}".red
      break
    end

    data = JSON.parse(resp.body)
    tags.concat(data.fetch('results', []).map { |t| t['name'] })

    url = data['next']
    break unless url
  end

  tags
end

# -- Streaming tar scanner ------------------------------------------------------
#
# Feeds decompressed gzip data into this object chunk by chunk. It walks tar
# headers (512 bytes each), skips file data blocks, and stops as soon as a
# path matching /assets/application-HASH.css is found. The caller can abort
# the HTTP download immediately after `found` is set, avoiding downloading the
# rest of the layer.

# Handles three tar long-name extensions:
#   PAX ('x'/'X' typeflag) - extended header with `path=<full>` key
#   GNU  ('L' typeflag)    - next data block is the full filename
#   USTAR prefix field     - 155-byte prefix at offset 345 prepended to name
#
# When sample_re is set, collects all matching filenames into #samples instead
# of stopping at the first CSS_HASH_RE match. Used for --sample diagnostics.
class TarCssScanner
  HEADER_SIZE = 512
  CSS_HASH_RE = %r{/assets/application-([a-f0-9]+)\.css\z}

  attr_reader :found, :samples

  def initialize
    @buf = ''.b
    @skip = 0
    @found = nil
    @pax_path = nil   # path extracted from PAX extended header
    @gnu_name = nil   # name extracted from GNU ././@LongLink block
    @collect_type = nil   # :pax or :gnu - currently collecting payload
    @collect_need = 0     # bytes still needed
    @collect_buf = ''.b
  end

  def <<(data)
    @buf << data.b
    step while @found.nil? && enough?
    self
  end

  private

  def enough?
    return !@buf.empty? if @collect_type

    @skip > 0 ? !@buf.empty? : @buf.size >= HEADER_SIZE
  end

  def step
    # -- collect mode: gather PAX / GNU payload ----------------------------
    if @collect_type
      take = [@collect_need, @buf.size].min
      @collect_buf << @buf.byteslice(0, take)
      @buf = @buf.byteslice(take..) || ''.b
      @collect_need -= take

      return unless @collect_need <= 0

      case @collect_type
      when :pax
        # PAX lines: "<decimal-len> <key>=<value>\n" - keep binary to match binary literals
        @collect_buf.scan(/\d+ path=([^\n]+)/) { |m| @pax_path = m[0] }
      when :gnu
        @gnu_name = @collect_buf.delete("\x00")
      end

      @collect_type = nil
      @collect_buf = ''.b
      return
    end

    # -- skip mode: discard data / padding blocks ---------------------------
    if @skip > 0
      take = [@skip, @buf.size].min
      @buf = @buf.byteslice(take..)
      @skip -= take
      return
    end

    # -- header mode --------------------------------------------------------
    header = @buf.byteslice(0, HEADER_SIZE)
    @buf = @buf.byteslice(HEADER_SIZE..) || ''.b
    typeflag = header.byteslice(156, 1) || "\x00"
    name = header.byteslice(0, 100).delete("\x00")
    size = header.byteslice(124, 12).strip.to_i(8)

    case typeflag
    when 'x', 'X' # PAX extended header
      padded = ((size + 511) / 512) * 512
      @collect_type = :pax
      @collect_need = padded
      @collect_buf = ''.b
    when 'L' # GNU long filename follows in data block
      padded = ((size + 511) / 512) * 512
      @collect_type = :gnu
      @collect_need = padded
      @collect_buf = ''.b
    else
      return if name.empty? # end-of-archive zero block

      # Reconstruct full path: PAX > GNU > USTAR-prefix+name
      effective = if @pax_path
                    @pax_path
                  elsif @gnu_name
                    @gnu_name
                  else
                    prefix = header.byteslice(345, 155).delete("\x00")
                    prefix.empty? ? name : "#{prefix}/#{name}"
                  end

      @pax_path = nil
      @gnu_name = nil

      if (m = effective.match(CSS_HASH_RE))
        @found = m[1]
        return
      end

      @skip = ((size + 511) / 512) * 512
    end
  end
end

# Collects every filename in a gzip-compressed tar layer that matches a regex.
# Never stops early - reads the whole stream. Used for --sample diagnostics.
class TarFilenameCollector
  HEADER_SIZE = 512

  attr_reader :filenames

  def initialize(pattern = /\.css\z/)
    @pattern = pattern
    @filenames = []
    @buf = ''.b
    @skip = 0
    @collect_type = nil
    @collect_need = 0
    @collect_buf = ''.b
    @pax_path = nil
    @gnu_name = nil
  end

  def <<(data)
    @buf << data.b
    step while enough?
    self
  end

  private

  def enough?
    return !@buf.empty? if @collect_type

    @skip > 0 ? !@buf.empty? : @buf.size >= HEADER_SIZE
  end

  def step
    if @collect_type
      take = [@collect_need, @buf.size].min
      @collect_buf << @buf.byteslice(0, take)
      @buf = @buf.byteslice(take..) || ''.b
      @collect_need -= take
      return unless @collect_need <= 0

      case @collect_type
      when :pax
        @collect_buf.scan(/\d+ path=([^\n]+)/) { |m| @pax_path = m[0] }
      when :gnu
        @gnu_name = @collect_buf.delete("\x00")
      end
      @collect_type = nil
      @collect_buf = ''.b
      return
    end

    if @skip > 0
      take = [@skip, @buf.size].min
      @buf = @buf.byteslice(take..)
      @skip -= take
      return
    end

    return unless @buf.size >= HEADER_SIZE

    header = @buf.byteslice(0, HEADER_SIZE)
    @buf = @buf.byteslice(HEADER_SIZE..) || ''.b
    typeflag = header.byteslice(156, 1) || "\x00"
    name = header.byteslice(0, 100).delete("\x00")
    size = header.byteslice(124, 12).strip.to_i(8)

    case typeflag
    when 'x', 'X'
      padded = ((size + 511) / 512) * 512
      @collect_type = :pax
      @collect_need = padded
      @collect_buf = ''.b
    when 'L'
      padded = ((size + 511) / 512) * 512
      @collect_type = :gnu
      @collect_need = padded
      @collect_buf = ''.b
    else
      return if name.empty?

      effective = if @pax_path then @pax_path
                  elsif @gnu_name then @gnu_name
                  else
                    prefix = header.byteslice(345, 155).delete("\x00")
                    prefix.empty? ? name : "#{prefix}/#{name}"
                  end
      @pax_path = nil
      @gnu_name = nil

      @filenames << effective if effective.match?(@pattern)
      @skip = ((size + 511) / 512) * 512
    end
  end
end

# -- Docker Registry API --------------------------------------------------------

def registry_token(repo)
  resp = http_get("#{AUTH_URL}&scope=repository:#{repo}:pull")
  JSON.parse(resp.body)['token']
end

def registry_get(uri, token)
  Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 15, read_timeout: 30) do |http|
    req = Net::HTTP::Get.new(uri)
    req['Authorization'] = "Bearer #{token}"
    req['Accept'] = MANIFEST_ACCEPT
    http.request(req)
  end
end

# Wraps registry_get with automatic retry on 429 (rate limit).
# Sleeps for Retry-After seconds (or exponential backoff) before retrying.
def registry_get_with_retry(uri, token, max_retries: 3)
  (max_retries + 1).times do |attempt|
    resp = registry_get(uri, token)
    return resp unless resp.code == '429'

    wait = [(resp['retry-after'].to_i.nonzero? || 2**attempt * 15), 120].min
    warn "  [rate limited (429), waiting #{wait}s before retry #{attempt + 1}/#{max_retries}]".yellow
    sleep wait
  end
  registry_get(uri, token)
end

# Returns the v2 image manifest for a given tag, resolving manifest lists to
# the linux/amd64 platform entry automatically.
# Returns nil on error, :expired on 401 (token needs refresh).
def fetch_manifest(repo, tag, token, verbose: false)
  uri = URI("#{REGISTRY}/#{repo}/manifests/#{tag}")
  resp = registry_get_with_retry(uri, token)
  return :expired if resp.code == '401'

  if !resp.is_a?(Net::HTTPSuccess)
    warn "  manifest #{tag}: HTTP #{resp.code}".yellow if verbose
    return nil
  end

  manifest = JSON.parse(resp.body)
  ct = resp['content-type'].to_s

  # Multi-platform manifest list - drill down to linux/amd64
  if ct.include?('manifest.list') || ct.include?('image.index')
    entry = manifest['manifests']&.find do |m|
      m.dig('platform', 'os') == 'linux' && m.dig('platform', 'architecture') == 'amd64'
    end
    return nil unless entry

    resp = registry_get_with_retry(URI("#{REGISTRY}/#{repo}/manifests/#{entry['digest']}"), token)
    return :expired if resp.code == '401'

    if !resp.is_a?(Net::HTTPSuccess)
      warn "  manifest #{tag} (amd64): HTTP #{resp.code}".yellow if verbose
      return nil
    end

    manifest = JSON.parse(resp.body)
  end

  manifest
end

# Streams a single gzip-compressed layer blob and scans tar headers for the
# application-HASH.css filename. Stops the download as soon as the hash is
# found - no need to consume the full layer.
#
# Registry blobs usually redirect (302) to cloud storage (S3/GCS/CDN); the
# redirect is followed manually so we never send the registry Bearer token to
# a third-party host.
def scan_layer(repo, digest, token, mediatype: nil, verbose: false)
  if mediatype&.include?('zstd')
    warn "    [skip zstd] #{digest[7, 16]}...".yellow if verbose
    return nil
  end
  warn "    [scan] #{digest[7, 16]}... (#{mediatype || 'unknown'})".cyan if verbose

  blob_uri = URI("#{REGISTRY}/#{repo}/blobs/#{digest}")
  redirect_uri = nil
  inline = nil

  # First request: registry endpoint - expect a 302 to cloud storage
  Net::HTTP.start(blob_uri.host, blob_uri.port, use_ssl: true,
                                                open_timeout: 15, read_timeout: 30) do |http|
    req = Net::HTTP::Get.new(blob_uri)
    req['Authorization'] = "Bearer #{token}"
    http.request(req) do |resp|
      case resp
      when Net::HTTPRedirection
        redirect_uri = URI(resp['location'])
      when Net::HTTPSuccess
        inline = scan_blob_stream(resp)
      end
    end
  end

  return inline unless redirect_uri

  # Second request: cloud storage - stream and scan, no auth header
  result = nil
  Net::HTTP.start(redirect_uri.host, redirect_uri.port, use_ssl: true,
                                                        open_timeout: 15, read_timeout: 300) do |http|
    req = Net::HTTP::Get.new(redirect_uri)
    http.request(req) do |resp|
      result = scan_blob_stream(resp) if resp.is_a?(Net::HTTPSuccess)
    end
  end
  result
rescue Zlib::Error, Errno::ECONNRESET, Net::ReadTimeout, OpenSSL::SSL::SSLError => e
  warn "    layer #{digest[7, 16]}... #{e.class}: #{e.message}".yellow
  nil
end

# Streams resp body through gzip decompression and a TarCssScanner.
# Throws :done as soon as the CSS hash is found so the caller's read_body
# loop exits early and the rest of the blob is not downloaded.
def scan_blob_stream(resp)
  return nil unless resp.is_a?(Net::HTTPSuccess)

  scanner = TarCssScanner.new
  inflater = Zlib::Inflate.new(Zlib::MAX_WBITS | 16) # gzip mode

  begin
    catch(:done) do
      resp.read_body do |chunk|
        scanner << inflater.inflate(chunk)
        throw :done if scanner.found
      end
    end
    scanner.found
  ensure
    begin
      inflater.close
    rescue StandardError
      nil
    end
  end
end

# Streams the full layer and collects every filename matching pattern.
def collect_layer_filenames(repo, digest, token, pattern: /\.css\z/)
  blob_uri = URI("#{REGISTRY}/#{repo}/blobs/#{digest}")
  redirect_uri = nil

  Net::HTTP.start(blob_uri.host, blob_uri.port, use_ssl: true,
                                                open_timeout: 15, read_timeout: 30) do |http|
    req = Net::HTTP::Get.new(blob_uri)
    req['Authorization'] = "Bearer #{token}"
    http.request(req) do |resp|
      return stream_filenames(resp, pattern) if resp.is_a?(Net::HTTPSuccess)

      redirect_uri = URI(resp['location']) if resp.is_a?(Net::HTTPRedirection)
    end
  end

  return [] unless redirect_uri

  Net::HTTP.start(redirect_uri.host, redirect_uri.port, use_ssl: true,
                                                        open_timeout: 15, read_timeout: 300) do |http|
    req = Net::HTTP::Get.new(redirect_uri)
    http.request(req) do |resp|
      return stream_filenames(resp, pattern) if resp.is_a?(Net::HTTPSuccess)
    end
  end
  []
rescue StandardError => e
  warn "  collect error: #{e.class}: #{e.message}".red
  []
end

def stream_filenames(resp, pattern)
  collector = TarFilenameCollector.new(pattern)
  inflater = Zlib::Inflate.new(Zlib::MAX_WBITS | 16)
  begin
    resp.read_body { |chunk| collector << inflater.inflate(chunk) }
    collector.filenames
  ensure
    begin
      inflater.close
    rescue StandardError
      nil
    end
  end
end

# Prints all filenames matching pattern across all layers of repo:tag.
def sample_tag(repo, tag, pattern: /\.css\z/)
  puts "\nSampling #{repo}:#{tag} for filenames matching #{pattern}...".cyan
  token = registry_token(repo)
  manifest = fetch_manifest(repo, tag, token)
  unless manifest
    warn '  Could not fetch manifest'.red
    return
  end

  layers = manifest['layers']&.reverse || []
  puts "  #{layers.size} layer(s), scanning newest-first...".cyan

  layers.each_with_index do |layer, idx|
    next if layer['mediaType']&.include?('zstd')

    print "  Layer #{idx + 1}/#{layers.size} #{layer['digest'][7, 16]}... "
    $stdout.flush
    files = collect_layer_filenames(repo, layer['digest'], token, pattern: pattern)
    puts "(#{files.size} match#{files.size == 1 ? '' : 'es'})"
    files.each { |f| puts "    #{f}" }
  end
end

# Fetches the manifest for repo:tag and scans layers newest-first.
# token_box is a single-element array [token] shared across threads; mutex
# protects refreshes so only one thread re-fetches when the token expires.
def get_css_hash(repo, tag, token_box, token_mutex, verbose: false)
  token = token_mutex.synchronize { token_box[0] }
  manifest = fetch_manifest(repo, tag, token, verbose: verbose)

  if manifest == :expired
    token_mutex.synchronize do
      # Only refresh if another thread hasn't already done it
      if token_box[0] == token
        token_box[0] = registry_token(repo)
        warn "  [token refreshed for #{repo}]".yellow if verbose
      end
    end
    token = token_mutex.synchronize { token_box[0] }
    manifest = fetch_manifest(repo, tag, token, verbose: verbose)
    return nil if manifest == :expired
  end

  return nil unless manifest

  layers = manifest['layers']&.reverse
  return nil if layers.nil? || layers.empty?

  warn "  #{layers.size} layer(s) found, scanning newest-first...".cyan if verbose
  layers.each do |layer|
    result = scan_layer(repo, layer['digest'], token, mediatype: layer['mediaType'], verbose: verbose)
    return result if result
  end
  nil
end

# -- JSON file helpers ----------------------------------------------------------

def load_json_map
  JSON.parse(File.read(JSON_FILE))
end

def max_version_in_map(data)
  data.values.flatten.filter_map { |v| parse_semver(v) }.max
end

def collapse_ranges(version_hashes)
  entries = []
  version_hashes.each do |ver, hash|
    if entries.last && entries.last[:hash] == hash
      entries.last[:high] = ver
    else
      entries << { hash: hash, low: ver, high: ver }
    end
  end
  entries
end

def write_json_map(data)
  lines = data.map { |k, v| "  #{k.to_json}: #{v.to_json}" }
  File.write(JSON_FILE, "{\n#{lines.join(",\n")}\n}\n")
end

def update_version_file(new_entries, dry_run:)
  data = load_json_map
  added = []
  updated = []

  new_entries.each do |e|
    if data.key?(e[:hash])
      # Hash already known - extend the high end of the range if the new version is higher.
      # When semvers are equal but suffixes differ, prefer -ee over -ce.
      existing_high_str = data[e[:hash]][1]
      existing_high = parse_semver(existing_high_str)
      new_high = parse_semver(e[:high])
      next unless new_high && existing_high

      cmp = new_high <=> existing_high
      next if cmp < 0
      # Same semver: only replace if we're upgrading from -ce to -ee
      next if cmp == 0 && !(existing_high_str.end_with?('-ce') && e[:high].end_with?('-ee'))

      data[e[:hash]][1] = e[:high] unless dry_run
      updated << e
    else
      data[e[:hash]] = [e[:low], e[:high]] unless dry_run
      added << e
    end
  end

  if added.empty? && updated.empty?
    puts 'No new entries to add - already up to date.'.green
    return
  end

  tag = dry_run ? ' [dry-run]' : ''
  unless added.empty?
    puts "\n#{added.size} new entr#{added.size == 1 ? 'y' : 'ies'} added#{tag}:".green
    added.each { |e| puts "  #{e[:hash].to_json}: #{[e[:low], e[:high]].to_json}" }
  end
  unless updated.empty?
    puts "\n#{updated.size} existing entr#{updated.size == 1 ? 'y' : 'ies'} range-extended#{tag}:".cyan
    updated.each { |e| puts "  #{e[:hash][0, 16]}... high -> #{e[:high]}" }
  end

  write_json_map(data) unless dry_run
end

def process_edition(edition, current_max, opts)
  repo = edition[:repo]
  tag_re = edition[:tag_re]
  label = edition[:label]
  version_fn = edition[:version_fn]

  puts "\nFetching GitLab #{label} tags from Docker Hub..."
  all_tags = fetch_all_tags(repo)
  puts "  #{all_tags.size} total tags fetched."

  candidates = all_tags.select { |t| tag_re.match?(t) }.select do |t|
    sv = tag_semver(t, tag_re)
    sv && (sv <=> current_max) > 0
  end.sort_by { |t| tag_semver(t, tag_re) }

  if candidates.empty?
    puts "  No new #{label} versions found.".green
    return []
  end

  puts "  Found #{candidates.size} new #{label} tag(s):".cyan
  candidates.each { |t| puts "    #{t}" }

  if opts[:dry_run]
    puts '[dry-run] skipping registry layer fetch'.cyan
    return candidates.map do |t|
      { hash: "dryrun#{'0' * 57}", low: version_fn.call(t), high: version_fn.call(t) }
    end
  end

  token_box = [registry_token(repo)]
  token_mutex = Mutex.new
  lock = Mutex.new
  results = {}
  work = Queue.new
  candidates.each { |t| work << t }

  puts "  Fetching CSS hashes (#{[MAX_CONCURRENT, candidates.size].min} parallel workers)...".cyan

  workers = [MAX_CONCURRENT, candidates.size].min.times.map do
    Thread.new do
      loop do
        tag = begin; work.pop(true); rescue ThreadError; break; end
        begin
          ver = version_fn.call(tag)
          hash = get_css_hash(repo, tag, token_box, token_mutex, verbose: opts[:verbose])
          lock.synchronize do
            if hash
              puts "  #{tag} ... #{hash[0, 16].green}..."
            else
              puts "  #{tag} ... #{'no CSS hash found'.yellow}"
            end
            results[tag] = [ver, hash] if hash
          end
        rescue StandardError => e
          lock.synchronize { warn "  #{tag} ... #{e.class}: #{e.message}".red }
        end
      end
    end
  end

  workers.each(&:join)

  ordered = candidates.filter_map { |t| results[t] }
  collapse_ranges(ordered)
end

# -- CLI -----------------------------------------------------------------------

options = { dry_run: false, verbose: false, sample: nil }

OptionParser.new do |opts|
  opts.banner = 'Usage: ruby tools/dev/update_gitlab_versions.rb [options]'
  opts.separator ''
  opts.separator 'Fetches GitLab EE/CE tags from Docker Hub, streams only the'
  opts.separator 'application layer from the Docker Registry API (no Docker daemon'
  opts.separator 'required), and updates version.json directly.'
  opts.separator ''

  opts.on('-n', '--dry-run', 'Show what would be added without modifying any files') do
    options[:dry_run] = true
  end

  opts.on('-v', '--verbose', 'Print layer mediatypes and scan progress') do
    options[:verbose] = true
  end

  opts.on('-s', '--sample REPO:TAG',
          'Dump all .css filenames from all layers of REPO:TAG (e.g. gitlab/gitlab-ce:17.0.0-ce.0)') do |val|
    options[:sample] = val
  end

  opts.on('-h', '--help', 'Display this help') do
    puts opts
    exit
  end
end.parse!

# -- sample mode ---------------------------------------------------------------

if options[:sample]
  repo, tag = options[:sample].split(':', 2)
  abort 'Usage: --sample REPO:TAG  (e.g. gitlab/gitlab-ce:17.0.0-ce.0)'.red unless repo && tag
  sample_tag(repo, tag)
  exit
end

# -- main ----------------------------------------------------------------------

data = load_json_map
current_max = max_version_in_map(data)
abort 'Could not determine current max version from version.json'.red unless current_max

puts "Current max version in GITLAB_CSS_MAP: #{current_max.join('.')}".cyan

all_entries = EDITIONS.flat_map { |ed| process_edition(ed, current_max, options) }

update_version_file(all_entries, dry_run: options[:dry_run])
