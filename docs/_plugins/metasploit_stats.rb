require 'jekyll'
require 'json'
require 'pathname'

#
# Helper class for extracting information related to Metasploit framework's stats
#
class MetasploitStats
  def total_module_count
    modules.length
  end

  # @return [Hash<String, Integer>] A map of module type to the amount of modules
  def module_counts
    module_counts_by_type = modules.group_by { |mod| mod['type'].to_s }.transform_values { |mods| mods.count }.sort_by(&:first).to_h
    module_counts_by_type
  end

  # @return [Array<Hash<String, Hash>>] A nested array of module metadata, containing at least the keys :name, :total, :children
  def nested_module_counts
    create_nested_module_counts(modules)
  end

  protected

  # @param [Array<Hash>] modules
  # @param [String] parent_path The parent path to track the nesting depth when called recursively
  #   i.e. auxiliary, then auxiliary/admin, then auxiliary/admin/foo, etc
  def create_nested_module_counts(modules, parent_path = '')
    # Group the modules by their prefix, i.e. auxiliary/payload/encoder/etc
    top_level_buckets = modules.select { |mod| mod['fullname'].start_with?(parent_path) }.group_by do |mod|
      remaining_paths = mod['fullname'].gsub(parent_path.empty? ? '' : %r{^#{parent_path}/}, '').split('/')
      remaining_paths[0]
    end.sort.to_h

    top_level_buckets.map do |(prefix, children)|
      current_path = parent_path.empty? ? prefix : "#{parent_path}/#{prefix}"
      mod = modules_by_fullname[current_path]
      {
        name: prefix,
        total: children.count,
        module_fullname: mod ?  mod['fullname'] : nil,
        module_path: mod ? mod['path'] : nil,
        children: mod.nil? ? create_nested_module_counts(children, current_path) : []
      }
    end
  end

  # @return [Array<Hash>] An array of Hashes containing each Metasploit module's metadata
  def modules
    return @modules if @modules

    module_metadata_path = '../db/modules_metadata_base.json'
    unless File.exist?(module_metadata_path)
      raise "Unable to find Metasploit module data, expected it to be at #{module_metadata_path}"
    end

    @modules = JSON.parse(File.binread(module_metadata_path)).values
    @modules
  end

  # @return [Hash<String, Hash>] A mapping of module name to Metasploit module metadata
  def modules_by_fullname
    @modules_by_fullname ||= @modules.each_with_object({}) do |mod, hash|
      fullname = mod['fullname']
      hash[fullname] = mod
    end
  end
end

# Custom liquid filter implementation for visualizing nested Metasploit module metadata
#
# Intended usage:
# {{ site.metasploit_nested_module_counts | module_tree }}
module ModuleFilter
  # @param [Array<Hash>] modules The array of Metasploit cache information
  # @return [String] The module tree HTML representation of the given modules
  def module_tree(modules, title = 'Modules', show_controls = false)
    rendered_children = render_modules(modules)
    controls = <<~EOF
        <div class="module-controls">
            <span><a href="#" data-expand-all>Expand All</a></span>
            <span><a href="#" data-collapse-all>Collapse All</a></span>
        </div>
    EOF

    <<~EOF
      <div class="module-list">
        #{show_controls ? controls : ''}

        <ul class="module-structure">
          <li class="folder"><a href=\"#\"><div class=\"target\">#{title}</div></a>
            <ul class="open">
              #{rendered_children}
            </ul>
          </li>
        </ul>
      </div>
    EOF
  end

  module_function

  # @param [Array<Hash>] modules The array of Metasploit cache information
  # @return [String] The rendered tree HTML representation of the given modules
  def render_modules(modules)
    modules.map do |mod|
      classes = render_child_modules?(mod) ? ' class="folder"' : ''
      result = "<li#{classes}>#{heading_for_mod(mod)}"
      if render_child_modules?(mod)
        result += "\n<ul>#{render_modules(mod[:children].sort_by { |mod| "#{render_child_modules?(mod) ? 0 : 1}-#{mod[:name]}" })}</ul>\n"
      end
      result += "</li>"
      result
    end.join("\n")
  end

  # @param [Hash] mod The module metadata object
  # @return [String] Human readable string for a module list such as `- <a>Auxiliary (1234)</a>` or `- Other (50)`
  def heading_for_mod(mod)
    if render_child_modules?(mod)
      "<a href=\"#\"><div class=\"target\">#{mod[:name]} (#{mod[:total]})</div></a>"
    else
      config = Jekyll.sites.first.config
      # Preference linking to module documentation over the module implementation
      module_docs_path = Pathname.new("documentation").join(mod[:module_path].gsub(/^\//, '')).sub_ext(".md")
      link_path = File.exist?(File.join('..', module_docs_path)) ? "/#{module_docs_path}" : mod[:module_path]
      docs_link = "#{config['gh_edit_repository']}/#{config['gh_edit_view_mode']}/#{config['gh_edit_branch']}#{link_path}"
      "<a href=\"#{docs_link}\" target=\"_blank\"><div class=\"target\">#{mod[:module_fullname]}</div></a>"
    end
  end

  # @param [Hash] mod The module metadata object
  # @return [TrueClass, FalseClass]
  def render_child_modules?(mod)
    mod[:children].length >= 1 && mod[:module_path].nil?
  end
end

# Register the Liquid filter so any Jekyll page can render module information
Liquid::Template.register_filter(ModuleFilter)

# Register the site initialization hook to populate global site information so any Jekyll page can access Metasploit stats information
Jekyll::Hooks.register :site, :after_init do |site|
  begin
    Jekyll.logger.info 'Calculating module stats'

    metasploit_stats = MetasploitStats.new

    site.config['metasploit_total_module_count'] = metasploit_stats.total_module_count
    site.config['metasploit_module_counts'] = metasploit_stats.module_counts
    site.config['metasploit_nested_module_counts'] = metasploit_stats.nested_module_counts

    Jekyll.logger.info 'Finished calculating module stats'
  rescue
    Jekyll.logger.error "Unable to to extractMetasploit stats"
    raise
  end
end
