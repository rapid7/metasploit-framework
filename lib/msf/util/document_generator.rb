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
      # @return [void]
      def self.spawn_module_document(mod)
        # By default, if there is a document already in the repository, then open that one.
        manual_path = File.join(PullRequestFinder::MANUAL_BASE_PATH, "#{mod.fullname}.md")

        # No document in the repo, then we generate one on the fly.
        unless File.exists?(manual_path)
          md = get_module_document(mod)
          f = Rex::Quickfile.new(["#{mod.shortname}_doc", '.html'])
          f.write(md)
          f.close
          manual_path = f.path
        end

        Rex::Compat.open_webrtc_browser("file://#{manual_path}")
      end


      # Returns a module document in HTML.
      #
      # @param mod [Msf::Module] Module to create document for.
      # @return [void]
      def self.get_module_document(mod)
        md = ''

        # If there is a document already in the repository, then open that one.
        manual_path = File.join(PullRequestFinder::MANUAL_BASE_PATH, "#{mod.fullname}.md")

        if File.exists?(manual_path)
          File.open(manual_path, 'rb') { |f| md = f.read }
        else
          begin
            pr_finder = PullRequestFinder.new
            pr = pr_finder.search(mod)
          rescue PullRequestFinder::Exception => e
            # This is a little weird, I guess, because the normalizer must handle two different
            # data types.
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
            mod_demo:          mod
          }

          if mod.respond_to?(:targets) && mod.targets
            items[:mod_targets] = mod.targets
          end

          md = n.get_md_content(items)
        end

        md
      end

    end
  end
end
