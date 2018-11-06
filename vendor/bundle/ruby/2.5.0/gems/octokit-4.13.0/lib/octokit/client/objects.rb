module Octokit
  class Client

    # Methods for the Git Data API
    #
    # @see https://developer.github.com/v3/git/
    module Objects

      # Get a single tree, fetching information about its root-level objects
      #
      # Pass <tt>:recursive => true</tt> in <tt>options</tt> to fetch information about all of the tree's objects, including those in subdirectories.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param tree_sha [String] The SHA of the tree to fetch
      # @return [Sawyer::Resource] A hash representing the fetched tree
      # @see https://developer.github.com/v3/git/trees/#get-a-tree
      # @see https://developer.github.com/v3/git/trees/#get-a-tree-recursively
      # @example Fetch a tree and inspect the path of one of its files
      #   tree = Octokit.tree("octocat/Hello-World", "9fb037999f264ba9a7fc6274d15fa3ae2ab98312")
      #   tree.tree.first.path # => "file.rb"
      # @example Fetch a tree recursively
      #   tree = Octokit.tree("octocat/Hello-World", "fc6274d15fa3ae2ab983129fb037999f264ba9a7", :recursive => true)
      #   tree.tree.first.path # => "subdir/file.txt"
      def tree(repo, tree_sha, options = {})
        get "#{Repository.path repo}/git/trees/#{tree_sha}", options
      end

      # Create a tree
      #
      # Pass <tt>:base_tree => "827efc6..."</tt> in <tt>options</tt> to update an existing tree with new data.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param tree [Array] An array of hashes representing a tree structure
      # @return [Sawyer::Resource] A hash representing the new tree
      # @see https://developer.github.com/v3/git/trees/#create-a-tree
      # @example Create a tree containing one file
      #   tree = Octokit.create_tree("octocat/Hello-World", [ { :path => "file.rb", :mode => "100644", :type => "blob", :sha => "44b4fc6d56897b048c772eb4087f854f46256132" } ])
      #   tree.sha # => "cd8274d15fa3ae2ab983129fb037999f264ba9a7"
      #   tree.tree.first.path # => "file.rb"
      def create_tree(repo, tree, options = {})
        parameters = { :tree => tree }
        post "#{Repository.path repo}/git/trees", options.merge(parameters)
      end

      # Get a single blob, fetching its content and encoding
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param blob_sha [String] The SHA of the blob to fetch
      # @return [Sawyer::Resource] A hash representing the fetched blob
      # @see https://developer.github.com/v3/git/blobs/#get-a-blob
      # @example Fetch a blob and inspect its contents
      #   blob = Octokit.blob("octocat/Hello-World", "827efc6d56897b048c772eb4087f854f46256132")
      #   blob.encoding # => "utf-8"
      #   blob.content # => "Foo bar baz"
      # @example Fetch a base64-encoded blob and inspect its contents
      #   require "base64"
      #   blob = Octokit.blob("octocat/Hello-World", "827efc6d56897b048c772eb4087f854f46256132")
      #   blob.encoding # => "base64"
      #   blob.content # => "Rm9vIGJhciBiYXo="
      #   Base64.decode64(blob.content) # => "Foo bar baz"
      def blob(repo, blob_sha, options = {})
        get "#{Repository.path repo}/git/blobs/#{blob_sha}", options
      end

      # Create a blob
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param content [String] Content of the blob
      # @param encoding [String] The content's encoding. <tt>utf-8</tt> and <tt>base64</tt> are accepted. If your data cannot be losslessly sent as a UTF-8 string, you can base64 encode it
      # @return [String] The new blob's SHA, e.g. <tt>827efc6d56897b048c772eb4087f854f46256132</tt>
      # @see https://developer.github.com/v3/git/blobs/#create-a-blob
      # @example Create a blob containing <tt>foo bar baz</tt>
      #   Octokit.create_blob("octocat/Hello-World", "foo bar baz")
      # @example Create a blob containing <tt>foo bar baz</tt>, encoded using base64
      #   require "base64"
      #   Octokit.create_blob("octocat/Hello-World", Base64.encode64("foo bar baz"), "base64")
      def create_blob(repo, content, encoding="utf-8", options = {})
        parameters = {
          :content => content,
          :encoding => encoding
        }
        blob = post "#{Repository.path repo}/git/blobs", options.merge(parameters)

        blob.sha
      end

      # Get a tag
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param tag_sha [String] The SHA of the tag to fetch.
      # @return [Sawyer::Resource] Hash representing the tag.
      # @see https://developer.github.com/v3/git/tags/#get-a-tag
      # @example Fetch a tag
      #   Octokit.tag('octokit/octokit.rb', '23aad20633f4d2981b1c7209a800db3014774e96')
      def tag(repo, tag_sha, options = {})
        get "#{Repository.path repo}/git/tags/#{tag_sha}", options
      end

      # Create a tag
      #
      # Requires authenticated client.
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository.
      # @param tag [String] Tag string.
      # @param message [String] Tag message.
      # @param object_sha [String] SHA of the git object this is tagging.
      # @param type [String] Type of the object we're tagging. Normally this is
      #   a `commit` but it can also be a `tree` or a `blob`.
      # @param tagger_name [String] Name of the author of the tag.
      # @param tagger_email [String] Email of the author of the tag.
      # @param tagger_date [string] Timestamp of when this object was tagged.
      # @return [Sawyer::Resource] Hash representing new tag.
      # @see https://developer.github.com/v3/git/tags/#create-a-tag-object
      # @example
      #   @client.create_tag(
      #     "octokit/octokit.rb",
      #     "v9000.0.0",
      #     "Version 9000\n",
      #     "f4cdf6eb734f32343ce3f27670c17b35f54fd82e",
      #     "commit",
      #     "Wynn Netherland",
      #     "wynn.netherland@gmail.com",
      #     "2012-06-03T17:03:11-07:00"
      #   )
      def create_tag(repo, tag, message, object_sha, type, tagger_name, tagger_email, tagger_date, options = {})
        options.merge!(
          :tag => tag,
          :message => message,
          :object => object_sha,
          :type => type,
          :tagger => {
            :name => tagger_name,
            :email => tagger_email,
            :date => tagger_date
          }
        )
        post "#{Repository.path repo}/git/tags", options
      end
    end
  end
end
