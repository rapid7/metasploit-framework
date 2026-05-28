#!/usr/bin/env ruby
# -*- coding: binary -*-

#
# by h00die
#
# Fetches all stable GitLab EE and CE Docker tags newer than the highest version
# already present in GITLAB_CSS_MAP, extracts the application CSS hash from each
# image (without starting GitLab), and writes new map entries directly into
# lib/msf/core/exploit/remote/http/gitlab/version.rb.
#
# Requirements: docker (authenticated if needed for private registries)
#
# Usage:
#   ruby tools/dev/update_gitlab_versions.rb [options]
#

require 'optparse'
require 'open3'
require 'net/http'
require 'uri'
require 'json'
require 'set'

# ── paths / constants ─────────────────────────────────────────────────────────

VERSION_FILE  = File.expand_path('../../lib/msf/core/exploit/remote/http/gitlab/version.rb', __dir__)
ASSET_GLOB    = '/opt/gitlab/embedded/service/gitlab-rails/public/assets/application-*.css'
CSS_HASH_RE   = /application-([a-f0-9]+)\.css/

# Stable release tag patterns — excludes rc, nightly, latest, etc.
# EE example: "17.3.2-ee.0"   CE example: "17.3.2-ce.0"
EE_TAG_RE = /\A(\d+)\.(\d+)\.(\d+)-ee\.(\d+)\z/
CE_TAG_RE = /\A(\d+)\.(\d+)\.(\d+)-ce\.(\d+)\z/

# Both EE and CE drop the .N suffix in map values: "17.3.2-ee", "17.3.2-ce".

EDITIONS = [
  { repo: 'gitlab/gitlab-ee', tag_re: EE_TAG_RE, label: 'EE',
    version_fn: ->(tag) { tag.sub(/-ee\.\d+\z/, '-ee') } },
  { repo: 'gitlab/gitlab-ce', tag_re: CE_TAG_RE, label: 'CE',
    version_fn: ->(tag) { tag.sub(/-ce\.\d+\z/, '-ce') } }
].freeze

# Insertion anchor — immediately before the }.freeze that closes GITLAB_CSS_MAP
ANCHOR_RE = /(\n  }\.freeze\n\n  include Msf::Exploit::Remote::HTTP::Gitlab::Rest::V4::Version)/

# ── colours ───────────────────────────────────────────────────────────────────

class String
  def red;    "\e[1;31;40m#{self}\e[0m"; end
  def yellow; "\e[1;33;40m#{self}\e[0m"; end
  def green;  "\e[1;32;40m#{self}\e[0m"; end
  def cyan;   "\e[1;36;40m#{self}\e[0m"; end
end

# ── helpers ───────────────────────────────────────────────────────────────────

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
  Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https') do |http|
    http.request(Net::HTTP::Get.new(uri))
  end
end

# ── Docker Hub tag enumeration ─────────────────────────────────────────────────

def fetch_all_tags(repo)
  tags = []
  url  = "https://hub.docker.com/v2/repositories/#{repo}/tags?page_size=100&ordering=last_updated"

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

# ── CSS hash extraction ────────────────────────────────────────────────────────

def pull_image(image, dry_run:)
  print "  pull #{image} ... "
  if dry_run
    puts '(dry-run)'.cyan
    return true
  end
  _, _, status = Open3.capture3('docker', 'pull', '--quiet', image)
  if status.success?
    puts 'ok'.green
    true
  else
    puts 'FAILED'.red
    false
  end
end

def get_css_hash(image, dry_run:)
  return 'dryrun0000000000000000000000000000000000000000000000000000000000' if dry_run

  stdout, _, status = Open3.capture3(
    'docker', 'run', '--rm', '--entrypoint', '/bin/sh',
    image, '-c', "ls #{ASSET_GLOB} 2>/dev/null | head -1"
  )
  return nil unless status.success?

  stdout.match(CSS_HASH_RE)&.[](1)
end

def remove_image(image, keep:)
  return if keep
  system('docker', 'rmi', '--force', image, out: File::NULL, err: File::NULL)
end

# ── Version file helpers ───────────────────────────────────────────────────────

def max_version_in_map(content)
  versions = content.scan(/=>\s*\['([^']+)',\s*'([^']+)'\]/).flatten
  versions.filter_map { |v| parse_semver(v) }.max
end

def existing_hashes(content)
  content.scan(/^\s+'([a-f0-9]{32,64})'\s*=>/).map(&:first).to_set
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

def update_version_file(new_entries, dry_run:)
  content = File.read(VERSION_FILE)
  known   = existing_hashes(content)
  to_add  = new_entries.reject { |e| known.include?(e[:hash]) }

  if to_add.empty?
    puts 'No new entries to add — already up to date.'.green
    return
  end

  ruby_lines = to_add.map do |e|
    "    '#{e[:hash]}' => ['#{e[:low]}', '#{e[:high]}'],"
  end.join("\n")

  updated = content.sub(ANCHOR_RE) { "\n#{ruby_lines}#{$1}" }

  if updated == content
    abort 'ERROR: could not find insertion point in version.rb — check ANCHOR_RE.'.red
  end

  if dry_run
    puts "\n[dry-run] Would add #{to_add.size} entries:".cyan
    to_add.each { |e| puts "  '#{e[:hash]}' => ['#{e[:low]}', '#{e[:high]}']" }
    return
  end

  File.write(VERSION_FILE, updated)
  puts "\nAdded #{to_add.size} new entries to #{VERSION_FILE}:".green
  to_add.each { |e| puts "  '#{e[:hash]}' => ['#{e[:low]}', '#{e[:high]}']" }
end

def process_edition(edition, current_max, opts)
  repo        = edition[:repo]
  tag_re      = edition[:tag_re]
  label       = edition[:label]
  version_fn  = edition[:version_fn]

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

  version_hashes = []

  candidates.each do |tag|
    image = "#{repo}:#{tag}"
    ver   = version_fn.call(tag)

    next unless pull_image(image, dry_run: opts[:dry_run])

    hash = get_css_hash(image, dry_run: opts[:dry_run])
    remove_image(image, keep: opts[:keep_images])

    if hash
      puts "    #{ver} => #{hash}".green
      version_hashes << [ver, hash]
    else
      puts "    WARNING: no CSS hash found for #{tag}".yellow
    end
  end

  collapse_ranges(version_hashes)
end

# ── CLI ───────────────────────────────────────────────────────────────────────

options = { keep_images: false, dry_run: false }

OptionParser.new do |opts|
  opts.banner = 'Usage: ruby tools/dev/update_gitlab_versions.rb [options]'
  opts.separator ''
  opts.separator 'Pulls all stable gitlab/gitlab-ee and gitlab/gitlab-ce images newer than'
  opts.separator 'the current max version in GITLAB_CSS_MAP, extracts the CSS fingerprint'
  opts.separator 'hash from each image, and updates version.rb directly.'
  opts.separator ''

  opts.on('-k', '--keep-images', 'Do not remove pulled Docker images after processing') do
    options[:keep_images] = true
  end

  opts.on('-n', '--dry-run', 'Show what would be added without modifying any files') do
    options[:dry_run] = true
  end

  opts.on('-h', '--help', 'Display this help') do
    puts opts
    exit
  end
end.parse!

# ── main ──────────────────────────────────────────────────────────────────────

content     = File.read(VERSION_FILE)
current_max = max_version_in_map(content)
abort 'Could not determine current max version from version.rb'.red unless current_max

puts "Current max version in GITLAB_CSS_MAP: #{current_max.join('.')}".cyan

all_entries = EDITIONS.flat_map { |ed| process_edition(ed, current_max, options) }

update_version_file(all_entries, dry_run: options[:dry_run])
