module Octokit
  class Client

    # Methods for the Repository Invitations API
    #
    # @see https://developer.github.com/v3/repos/invitations/
    module RepositoryInvitations

      # Invite a user to a repository
      #
      # Requires authenticated client
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param user [String] User GitHub username to add
      # @return [Sawyer::Resource] The repository invitation
      # @see https://developer.github.com/v3/repos/invitations/#invite-a-user-to-a-repository
      def invite_user_to_repository(repo, user, options = {})
        put "#{Repository.path repo}/collaborators/#{user}", options
      end
      alias invite_user_to_repo invite_user_to_repository

      # List all invitations for a repository
      #
      # Requires authenticated client
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @return [Array<Sawyer::Resource>] A list of invitations
      # @see https://developer.github.com/v3/repos/invitations/#list-invitations-for-a-repository
      def repository_invitations(repo, options = {})
        paginate "#{Repository.path repo}/invitations", options
      end
      alias repo_invitations repository_invitations

      # Delete an invitation for a repository
      #
      # Requires authenticated client
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param invitation_id [Integer] The id of the invitation
      # @return [Boolean] True if the invitation was successfully deleted
      # @see https://developer.github.com/v3/repos/invitations/#delete-a-repository-invitation
      def delete_repository_invitation(repo, invitation_id, options = {})
        boolean_from_response :delete, "#{Repository.path repo}/invitations/#{invitation_id}", options
      end
      alias delete_repo_invitation delete_repository_invitation

      # Update an invitation for a repository
      #
      # Requires authenticated client
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param invitation_id [Integer] The id of the invitation
      # @return [Sawyer::Resource] The updated repository invitation
      # @see https://developer.github.com/v3/repos/invitations/#update-a-repository-invitation
      def update_repository_invitation(repo, invitation_id, options = {})
        patch "#{Repository.path repo}/invitations/#{invitation_id}", options
      end
      alias update_repo_invitation update_repository_invitation

      # List all repository invitations for the user
      #
      # Requires authenticated client
      #
      # @return [Array<Sawyer::Resource>] The users repository invitations
      # @see https://developer.github.com/v3/repos/invitations/#list-a-users-repository-invitations
      def user_repository_invitations(options = {})
        paginate "/user/repository_invitations", options
      end
      alias user_repo_invitations user_repository_invitations

      # Accept a repository invitation
      #
      # Requires authenticated client
      #
      # @param invitation_id [Integer] The id of the invitation
      # @return [Boolean] True if the acceptance of the invitation was successful
      # @see https://developer.github.com/v3/repos/invitations/#accept-a-repository-invitation
      def accept_repository_invitation(invitation_id, options = {})
        patch "/user/repository_invitations/#{invitation_id}", options
      end
      alias accept_repo_invitation accept_repository_invitation

      # Decline a repository invitation
      #
      # Requires authenticated client
      #
      # @param invitation_id [Integer] The id of the invitation
      # @return [Boolean] True if the acceptance of the invitation was successful
      # @see https://developer.github.com/v3/repos/invitations/#decline-a-repository-invitation
      def decline_repository_invitation(invitation_id, options = {})
        boolean_from_response :delete, "/user/repository_invitations/#{invitation_id}", options
      end
      alias decline_invitation decline_repository_invitation
    end
  end
end
