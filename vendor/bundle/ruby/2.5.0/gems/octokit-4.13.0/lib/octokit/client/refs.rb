module Octokit
  class Client

    # Methods for References for Git Data API
    #
    # @see https://developer.github.com/v3/git/refs/
    module Refs

      # List all refs for a given user and repo
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param namespace [String] The ref namespace, e.g. <tt>tag</tt> or <tt>heads</tt>
      # @return [Array<Sawyer::Resource>] A list of references matching the repo and the namespace
      # @see https://developer.github.com/v3/git/refs/#get-all-references
      # @example Fetch all refs for sferik/rails_admin
      #   Octokit.refs("sferik/rails_admin")
      def refs(repo, namespace = nil, options = {})
        path = "#{Repository.path repo}/git/refs"
        path += "/#{namespace}" unless namespace.nil?
        paginate path, options
      end
      alias :list_refs :refs
      alias :references :refs
      alias :list_references :refs

      # Fetch a given reference
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param ref [String] The ref, e.g. <tt>tags/v0.0.3</tt>
      # @return [Sawyer::Resource] The reference matching the given repo and the ref id
      # @see https://developer.github.com/v3/git/refs/#get-a-reference
      # @example Fetch tags/v0.0.3 for sferik/rails_admin
      #   Octokit.ref("sferik/rails_admin","tags/v0.0.3")
      def ref(repo, ref, options = {})
        get "#{Repository.path repo}/git/refs/#{ref}", options
      end
      alias :reference :ref

      # Create a reference
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param ref [String] The ref, e.g. <tt>tags/v0.0.3</tt>
      # @param sha [String] A SHA, e.g. <tt>827efc6d56897b048c772eb4087f854f46256132</tt>
      # @return [Array<Sawyer::Resource>] The list of references, already containing the new one
      # @see https://developer.github.com/v3/git/refs/#create-a-reference
      # @example Create refs/heads/master for octocat/Hello-World with sha 827efc6d56897b048c772eb4087f854f46256132
      #   Octokit.create_ref("octocat/Hello-World", "heads/master", "827efc6d56897b048c772eb4087f854f46256132")
      def create_ref(repo, ref, sha, options = {})
        ref = "refs/#{ref}" unless ref =~ %r{refs/}
        parameters = {
          :ref  => ref,
          :sha  => sha
        }
        post "#{Repository.path repo}/git/refs", options.merge(parameters)
      end
      alias :create_reference :create_ref

      # Update a reference
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param ref [String] The ref, e.g. <tt>tags/v0.0.3</tt>
      # @param sha [String] A SHA, e.g. <tt>827efc6d56897b048c772eb4087f854f46256132</tt>
      # @param force [Boolean] A flag indicating one wants to force the update to make sure the update is a fast-forward update.
      # @return [Array<Sawyer::Resource>] The list of references updated
      # @see https://developer.github.com/v3/git/refs/#update-a-reference
      # @example Force update heads/sc/featureA for octocat/Hello-World with sha aa218f56b14c9653891f9e74264a383fa43fefbd
      #   Octokit.update_ref("octocat/Hello-World", "heads/sc/featureA", "aa218f56b14c9653891f9e74264a383fa43fefbd")
      def update_ref(repo, ref, sha, force = true, options = {})
        parameters = {
          :sha  => sha,
          :force => force
        }
        patch "#{Repository.path repo}/git/refs/#{ref}", options.merge(parameters)
      end
      alias :update_reference :update_ref

      # Update a branch
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param branch [String] The ref, e.g. <tt>feature/new-shiny</tt>
      # @param sha [String] A SHA, e.g. <tt>827efc6d56897b048c772eb4087f854f46256132</tt>
      # @param force [Boolean] A flag indicating one wants to force the update to make sure the update is a fast-forward update.
      # @return [Array<Sawyer::Resource>] The list of references updated
      # @see https://developer.github.com/v3/git/refs/#update-a-reference
      # @example Force update heads/sc/featureA for octocat/Hello-World with sha aa218f56b14c9653891f9e74264a383fa43fefbd
      #   Octokit.update_ref("octocat/Hello-World","sc/featureA", "aa218f56b14c9653891f9e74264a383fa43fefbd")
      def update_branch(repo, branch, sha, force = true, options = {})
        update_ref repo, "heads/#{branch}", sha, force, options
      end

      # Delete a single branch
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param branch [String] The branch, e.g. <tt>fix-refs</tt>
      # @return [Boolean] Success
      # @see https://developer.github.com/v3/git/refs/#delete-a-reference
      # @example Delete uritemplate for sigmavirus24/github3.py
      #   Octokit.delete_branch("sigmavirus24/github3.py", "uritemplate")
      def delete_branch(repo, branch, options = {})
        delete_ref repo, "heads/#{branch}", options
      end

      # Delete a single reference
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param ref [String] The ref, e.g. <tt>tags/v0.0.3</tt>
      # @return [Boolean] Success
      # @see https://developer.github.com/v3/git/refs/#delete-a-reference
      # @example Delete tags/v0.0.3 for sferik/rails_admin
      #   Octokit.delete_ref("sferik/rails_admin","tags/v0.0.3")
      def delete_ref(repo, ref, options = {})
        boolean_from_response :delete, "#{Repository.path repo}/git/refs/#{ref}", options
      end
      alias :delete_reference :delete_ref

    end
  end
end
