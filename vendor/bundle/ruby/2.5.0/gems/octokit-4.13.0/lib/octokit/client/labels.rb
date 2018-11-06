require 'cgi'

module Octokit
  class Client

    # Methods for the Issue Labels API
    #
    # @see https://developer.github.com/v3/issues/labels/
    module Labels

      # List available labels for a repository
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @return [Array<Sawyer::Resource>] A list of the labels across the repository
      # @see https://developer.github.com/v3/issues/labels/#list-all-labels-for-this-repository
      # @example List labels for octokit/octokit.rb
      #   Octokit.labels("octokit/octokit.rb")
      def labels(repo, options = {})
        paginate "#{Repository.path repo}/labels", options
      end

      # Get single label for a repository
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param name [String] Name of the label
      # @return [Sawyer::Resource] A single label from the repository
      # @see https://developer.github.com/v3/issues/labels/#get-a-single-label
      # @example Get the "V3 Addition" label from octokit/octokit.rb
      #   Octokit.label("octokit/octokit.rb", "V3 Addition")
      def label(repo, name, options = {})
        get "#{Repository.path repo}/labels/#{name}", options
      end

      # Add a label to a repository
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param label [String] A new label
      # @param color [String] A color, in hex, without the leading #
      # @return [Sawyer::Resource] The new label
      # @see https://developer.github.com/v3/issues/labels/#create-a-label
      # @example Add a new label "Version 1.0" with color "#cccccc"
      #   Octokit.add_label("octokit/octokit.rb", "Version 1.0", "cccccc")
      def add_label(repo, label, color="ffffff", options = {})
        post "#{Repository.path repo}/labels", options.merge({:name => label, :color => color})
      end

      # Update a label
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param label [String] The name of the label which will be updated
      # @param options [Hash] A customizable set of options.
      # @option options [String] :name An updated label name
      # @option options [String] :color An updated color value, in hex, without leading #
      # @return [Sawyer::Resource] The updated label
      # @see https://developer.github.com/v3/issues/labels/#update-a-label
      # @example Update the label "Version 1.0" with new color "#cceeaa"
      #   Octokit.update_label("octokit/octokit.rb", "Version 1.0", {:color => "cceeaa"})
      def update_label(repo, label, options = {})
        patch "#{Repository.path repo}/labels/#{label}", options
      end

      # Delete a label from a repository.
      #
      # This deletes the label from the repository, and removes it from all issues.
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param label [String] String name of the label
      # @return [Boolean] Success
      # @see https://developer.github.com/v3/issues/labels/#delete-a-label
      # @example Delete the label "Version 1.0" from the repository.
      #   Octokit.delete_label!("octokit/octokit.rb", "Version 1.0")
      def delete_label!(repo, label, options = {})
        boolean_from_response :delete, "#{Repository.path repo}/labels/#{label}", options
      end

      # Remove a label from an Issue
      #
      # This removes the label from the Issue
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Number ID of the issue
      # @param label [String] String name of the label
      # @return [Array<Sawyer::Resource>] A list of the labels currently on the issue
      # @see https://developer.github.com/v3/issues/labels/#remove-a-label-from-an-issue
      # @example Remove the label "Version 1.0" from the repository.
      #   Octokit.remove_label("octokit/octokit.rb", 23, "Version 1.0")
      def remove_label(repo, number, label, options = {})
        delete "#{Repository.path repo}/issues/#{number}/labels/#{label}", options
      end

      # Remove all label from an Issue
      #
      # This removes the label from the Issue
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Number ID of the issue
      # @return [Boolean] Success of operation
      # @see https://developer.github.com/v3/issues/labels/#remove-all-labels-from-an-issue
      # @example Remove all labels from Issue #23
      #   Octokit.remove_all_labels("octokit/octokit.rb", 23)
      def remove_all_labels(repo, number, options = {})
        boolean_from_response :delete, "#{Repository.path repo}/issues/#{number}/labels", options
      end

      # List labels for a given issue
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Number ID of the issue
      # @return [Array<Sawyer::Resource>] A list of the labels currently on the issue
      # @see https://developer.github.com/v3/issues/labels/#list-labels-on-an-issue
      # @example List labels for octokit/octokit.rb, issue # 1
      #   Octokit.labels_for_issue("octokit/octokit.rb", 1)
      def labels_for_issue(repo, number, options = {})
        paginate "#{Repository.path repo}/issues/#{number}/labels", options
      end

      # Add label(s) to an Issue
      #
      # @param repo [Integer, String, Repository, Hash] A Github repository
      # @param number [Integer] Number ID of the issue
      # @param labels [Array] An array of labels to apply to this Issue
      # @return [Array<Sawyer::Resource>] A list of the labels currently on the issue
      # @see https://developer.github.com/v3/issues/labels/#add-labels-to-an-issue
      # @example Add two labels for octokit/octokit.rb
      #   Octokit.add_labels_to_an_issue("octokit/octokit.rb", 10, ['V3 Transition', 'Improvement'])
      def add_labels_to_an_issue(repo, number, labels)
        post "#{Repository.path repo}/issues/#{number}/labels", labels
      end

      # Replace all labels on an Issue
      #
      # @param repo [Integer, String, Repository, Hash] A Github repository
      # @param number [Integer] Number ID of the issue
      # @param labels [Array] An array of labels to use as replacement
      # @return [Array<Sawyer::Resource>] A list of the labels currently on the issue
      # @see https://developer.github.com/v3/issues/labels/#replace-all-labels-for-an-issue
      # @example Replace labels for octokit/octokit.rb Issue #10
      #   Octokit.replace_all_labels("octokit/octokit.rb", 10, ['V3 Transition', 'Improvement'])
      def replace_all_labels(repo, number, labels, options = {})
        put "#{Repository.path repo}/issues/#{number}/labels", labels
      end

      # Get labels for every issue in a milestone
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param number [Integer] Number ID of the milestone
      # @return [Array<Sawyer::Resource>] A list of the labels across the milestone
      # @see  http://developer.github.com/v3/issues/labels/#get-labels-for-every-issue-in-a-milestone
      # @example List all labels for milestone #2 on octokit/octokit.rb
      #   Octokit.labels_for_milestone("octokit/octokit.rb", 2)
      def labels_for_milestone(repo, number, options = {})
        paginate "#{Repository.path repo}/milestones/#{number}/labels", options
      end
    end
  end
end
