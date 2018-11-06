# frozen_string_literal: true
module YARD
  module Server
    module Commands
      # Performs a search over the objects inside of a library and returns
      # the results as HTML or plaintext
      class SearchCommand < LibraryCommand
        include Templates::Helpers::BaseHelper
        include Templates::Helpers::ModuleHelper
        include DocServerHelper

        attr_accessor :results, :query

        def run
          Registry.load_all
          self.query = request.query['q']
          redirect(abs_url(adapter.router.docs_prefix, single_library ? library : '')) if query.nil? || query =~ /\A\s*\Z/

          found = Registry.at(query)
          redirect(url_for(found)) if found

          search_for_object
          request.xhr? ? serve_xhr : serve_normal
        end

        def visible_results
          results[0, 10]
        end

        private

        def url_for(object)
          abs_url(base_path(router.docs_prefix),
            serializer.serialized_path(object))
        end

        def serve_xhr
          headers['Content-Type'] = 'text/plain'
          self.body = visible_results.map {|o|
            [(o.type == :method ? o.name(true) : o.name).to_s,
             o.path,
             o.namespace.root? ? '' : o.namespace.path,
             url_for(o)].join(",")
          }.join("\n")
        end

        def serve_normal
          options.update(
            :visible_results => visible_results,
            :query => query,
            :results => results,
            :template => :doc_server,
            :type => :search
          )
          self.body = Templates::Engine.render(options)
        end

        def search_for_object
          # rubocop:disable Style/MultilineBlockChain
          self.results = run_verifier(Registry.all).select do |o|
            o.path.downcase.include?(query.downcase)
          end.reject do |o|
            name = (o.type == :method ? o.name(true) : o.name).to_s.downcase
            !name.include?(query.downcase) ||
              case o.type
              when :method
                !(query =~ /[#.]/) && query.include?("::")
              when :class, :module, :constant, :class_variable
                query =~ /[#.]/
              end
          end.sort_by do |o|
            name = (o.type == :method ? o.name(true) : o.name).to_s
            name.length.to_f / query.length.to_f
          end
        end
      end
    end
  end
end
