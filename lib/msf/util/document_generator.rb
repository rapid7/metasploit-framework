###
#
# This provides methods to generate documentation for a module.
#
###

require 'msf/util/document_generator/pull_request_finder'
require 'msf/util/document_generator/normalizer'

module Msf
  module Util
    module DocumentGenerator


      # Spawns a module document with a browser locally.
      #
      # @param mod [Msf::Module] Module to create document for.
      # @param out_file [Rex::Quickfile] File handle to write the document to.
      # @return [void]
      def self.spawn_module_document(mod, out_file)
        md = get_module_document(mod)
        out_file.write(md)
        Rex::Compat.open_webrtc_browser("file://#{out_file.path}")
      end


      # Returns a module document in HTML.
      #
      # @param mod [Msf::Module] Module to create document for.
      # @return [void]
      def self.get_module_document(mod)
        kb_path = nil
        kb = ''

        user_path = File.join(PullRequestFinder::USER_MANUAL_BASE_PATH, "#{mod.fullname}.md")
        global_path = File.join(PullRequestFinder::MANUAL_BASE_PATH, "#{mod.fullname}.md")

        if File.exists?(user_path)
          kb_path = user_path
        elsif File.exists?(global_path)
          kb_path = global_path
        end

        unless kb_path.nil?
          File.open(kb_path, 'rb') { |f| kb = f.read }
        end

        begin
          pr_finder = PullRequestFinder.new
          pr = pr_finder.search(mod)
        rescue PullRequestFinder::Exception => e
          pr = e
        end

        n = DocumentNormalizer.new
          items = {
            mod_description:   mod.description,
            mod_authors:       mod.send(:module_info)['Author'],
            mod_fullname:      mod.fullname,
            mod_name:          mod.name,
            mod_pull_requests: pr,
            mod_refs:          mod.references,
            mod_rank:          mod.rank,
            mod_platforms:     mod.send(:module_info)['Platform'],
            mod_options:       mod.options,
            mod_side_effects:  mod.side_effects,
            mod_reliability:   mod.reliability,
            mod_stability:     mod.stability,
            mod_demo:          mod
        }

        if mod.respond_to?(:targets) && mod.targets
          items[:mod_targets] = mod.targets
        end

        n.get_md_content(items, kb)
      end

    end
  end
end
