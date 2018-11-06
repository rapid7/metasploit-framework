# frozen_string_literal: true
#--
# Copyright 2006 by Chad Fowler, Rich Kilmer, Jim Weirich and others.
# All rights reserved.
# See LICENSE.txt for permissions.
#++

require 'rubygems/specification'

##
# The SourceIndex object indexes all the gems available from a
# particular source (e.g. a list of gem directories, or a remote
# source).  A SourceIndex maps a gem full name to a gem
# specification.
#
# NOTE:: The class used to be named Cache, but that became
#        confusing when cached source fetchers where introduced. The
#        constant Gem::Cache is an alias for this class to allow old
#        YAMLized source index objects to load properly.

class Gem::SourceIndex
  # Undef old methods
  alias old_initialize initialize
  undef old_initialize
  %w(all_gems prerelease_gems load_gems_in latest_specs prerelease_specs
      released_specs add_spec add_specs remove_spec each specification
      index_signature gem_signature size length find_name search released_gems
      refresh! outdated == dump gems spec_dirs spec_dirs=).each do |meth|
    undef_method(meth) if method_defined?(meth)
  end

  include Enumerable

  attr_reader :gems # :nodoc:

  ##
  # Directories to use to refresh this SourceIndex when calling refresh!

  attr_accessor :spec_dirs

  class << self
    # Undef old methods
    %w(from_installed_gems installed_spec_directories
        from_gems_in load_specification).each do |meth|
      undef_method(meth) if instance_methods(true).find {|m| m.to_s == meth }
    end

    ##
    # Factory method to construct a source index instance for a given
    # path.
    #
    # deprecated::
    #   If supplied, from_installed_gems will act just like
    #   +from_gems_in+.  This argument is deprecated and is provided
    #   just for backwards compatibility, and should not generally
    #   be used.
    #
    # return::
    #   SourceIndex instance

    def from_installed_gems(*deprecated)
      if deprecated.empty?
        from_gems_in(*installed_spec_directories)
      else
        from_gems_in(*deprecated) # HACK: warn
      end
    end

    ##
    # Returns a list of directories from Gem.path that contain specifications.

    def installed_spec_directories
      Gem.path.collect {|dir| File.join(dir, "specifications") }
    end

    ##
    # Creates a new SourceIndex from the ruby format gem specifications in
    # +spec_dirs+.

    def from_gems_in(*spec_dirs)
      source_index = new
      source_index.spec_dirs = spec_dirs
      source_index.refresh!
    end

    ##
    # Loads a ruby-format specification from +file_name+ and returns the
    # loaded spec.

    def load_specification(file_name)
      Gem::Specification.load file_name
    end
  end

  ##
  # Constructs a source index instance from the provided specifications, which
  # is a Hash of gem full names and Gem::Specifications.
  #--
  # TODO merge @gems and @prerelease_gems and provide a separate method
  # #prerelease_gems

  def initialize(specifications = {})
    @gems = {}
    specifications.each {|_full_name, spec| add_spec spec }
    @spec_dirs = nil
  end

  # TODO: remove method
  def all_gems
    @gems
  end

  def prerelease_gems
    @gems.reject {|_name, gem| !gem.version.prerelease? }
  end

  def released_gems
    @gems.reject {|_name, gem| gem.version.prerelease? }
  end

  ##
  # Reconstruct the source index from the specifications in +spec_dirs+.

  def load_gems_in(*spec_dirs)
    @gems.clear

    spec_dirs.reverse_each do |spec_dir|
      spec_files = Dir.glob File.join(spec_dir, '*.gemspec')

      spec_files.each do |spec_file|
        gemspec = Gem::Specification.load spec_file
        add_spec gemspec if gemspec
      end
    end

    self
  end

  ##
  # Returns an Array specifications for the latest released versions
  # of each gem in this index.

  def latest_specs(include_prerelease = false)
    result = Hash.new {|h, k| h[k] = [] }
    latest = {}

    sort.each do |_, spec|
      name = spec.name
      curr_ver = spec.version
      prev_ver = latest.key?(name) ? latest[name].version : nil

      next if !include_prerelease && curr_ver.prerelease?
      next unless prev_ver.nil? || curr_ver >= prev_ver ||
                  latest[name].platform != Gem::Platform::RUBY

      if prev_ver.nil? ||
         (curr_ver > prev_ver && spec.platform == Gem::Platform::RUBY)
        result[name].clear
        latest[name] = spec
      end

      if spec.platform != Gem::Platform::RUBY
        result[name].delete_if do |result_spec|
          result_spec.platform == spec.platform
        end
      end

      result[name] << spec
    end

    # TODO: why is this a hash while @gems is an array? Seems like
    # structural similarity would be good.
    result.values.flatten
  end

  ##
  # An array including only the prerelease gemspecs

  def prerelease_specs
    prerelease_gems.values
  end

  ##
  # An array including only the released gemspecs

  def released_specs
    released_gems.values
  end

  ##
  # Add a gem specification to the source index.

  def add_spec(gem_spec, name = gem_spec.full_name)
    # No idea why, but the Indexer wants to insert them using original_name
    # instead of full_name. So we make it an optional arg.
    @gems[name] = gem_spec
  end

  ##
  # Add gem specifications to the source index.

  def add_specs(*gem_specs)
    gem_specs.each do |spec|
      add_spec spec
    end
  end

  ##
  # Remove a gem specification named +full_name+.

  def remove_spec(full_name)
    @gems.delete full_name
  end

  ##
  # Iterate over the specifications in the source index.

  def each(&block) # :yields: gem.full_name, gem
    @gems.each(&block)
  end

  ##
  # The gem specification given a full gem spec name.

  def specification(full_name)
    @gems[full_name]
  end

  ##
  # The signature for the source index.  Changes in the signature indicate a
  # change in the index.

  def index_signature
    require 'digest'

    Digest::SHA256.new.hexdigest(@gems.keys.sort.join(',')).to_s
  end

  ##
  # The signature for the given gem specification.

  def gem_signature(gem_full_name)
    require 'digest'

    Digest::SHA256.new.hexdigest(@gems[gem_full_name].to_yaml).to_s
  end

  def size
    @gems.size
  end
  alias length size

  ##
  # Find a gem by an exact match on the short name.

  def find_name(gem_name, requirement = Gem::Requirement.default)
    dep = Gem::Dependency.new gem_name, requirement
    search dep
  end

  ##
  # Search for a gem by Gem::Dependency +gem_pattern+.  If +only_platform+
  # is true, only gems matching Gem::Platform.local will be returned.  An
  # Array of matching Gem::Specification objects is returned.
  #
  # For backwards compatibility, a String or Regexp pattern may be passed as
  # +gem_pattern+, and a Gem::Requirement for +platform_only+.  This
  # behavior is deprecated and will be removed.

  def search(gem_pattern, platform_only = false)
    requirement = nil
    only_platform = false

    # TODO: Remove support and warning for legacy arguments after 2008/11
    unless Gem::Dependency === gem_pattern
      warn "#{Gem.location_of_caller.join ':'}:Warning: Gem::SourceIndex#search support for #{gem_pattern.class} patterns is deprecated, use #find_name"
    end

    case gem_pattern
    when Regexp then
      requirement = platform_only || Gem::Requirement.default
    when Gem::Dependency then
      only_platform = platform_only
      requirement = gem_pattern.requirement

      gem_pattern = if Regexp === gem_pattern.name
                      gem_pattern.name
                    elsif gem_pattern.name.empty?
                      //
                    else
                      /^#{Regexp.escape gem_pattern.name}$/
                    end
    else
      requirement = platform_only || Gem::Requirement.default
      gem_pattern = /#{gem_pattern}/i
    end

    unless Gem::Requirement === requirement
      requirement = Gem::Requirement.create requirement
    end

    specs = all_gems.values.select do |spec|
      spec.name =~ gem_pattern &&
        requirement.satisfied_by?(spec.version)
    end

    if only_platform
      specs = specs.select do |spec|
        Gem::Platform.match spec.platform
      end
    end

    specs.sort_by(&:sort_obj)
  end

  ##
  # Replaces the gems in the source index from specifications in the
  # directories this source index was created from.  Raises an exception if
  # this source index wasn't created from a directory (via from_gems_in or
  # from_installed_gems, or having spec_dirs set).

  def refresh!
    raise 'source index not created from disk' if @spec_dirs.nil?
    load_gems_in(*@spec_dirs)
  end

  ##
  # Returns an Array of Gem::Specifications that are not up to date.

  def outdated
    outdateds = []

    latest_specs.each do |local|
      dependency = Gem::Dependency.new local.name, ">= #{local.version}"

      fetcher = Gem::SpecFetcher.fetcher
      remotes = fetcher.find_matching dependency
      remotes = remotes.map {|(_, version, _), _| version }

      latest = remotes.sort.last

      outdateds << local.name if latest && local.version < latest
    end

    outdateds
  end

  def ==(other) # :nodoc:
    self.class === other && @gems == other.gems
  end

  def dump
    Marshal.dump(self)
  end
end

# :stopdoc:
module Gem
  ##
  # Cache is an alias for SourceIndex to allow older YAMLized source index
  # objects to load properly.

  Cache = SourceIndex unless defined?(Cache)
end
# :startdoc:
