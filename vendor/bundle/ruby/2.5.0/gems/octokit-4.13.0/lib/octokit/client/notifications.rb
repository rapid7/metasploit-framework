module Octokit
  class Client

    # Methods for the Notifications API
    #
    # @see https://developer.github.com/v3/activity/notifications/
    module Notifications

      # List your notifications
      #
      # @param options [Hash] Optional parameters
      # @option options [Boolean] :all 'true' to show notifications marked as
      #   read.
      # @option options [Boolean] :participating 'true' to show only
      #   notifications in which the user is directly participating or
      #   mentioned.
      # @option options [String] :since Time filters out any notifications
      #   updated before the given time. The time should be passed in as UTC in
      #   the ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ. Ex. '2012-10-09T23:39:01Z'
      # @return [Array<Sawyer::Resource>] Array of notifications.
      # @see https://developer.github.com/v3/activity/notifications/#list-your-notifications
      # @example Get users notifications
      #   @client.notifications
      # @example Get all notifications since a certain time.
      #   @client.notifications({all: true, since: '2012-10-09T23:39:01Z'})
      def notifications(options = {})
        paginate "notifications", options
      end

      # List your notifications in a repository
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param options [Hash] Optional parameters
      # @option options [Boolean] :all 'true' to show notifications marked as
      #   read.
      # @option options [Boolean] :participating 'true' to show only
      #   notifications in which the user is directly participating or
      #   mentioned.
      # @option options [String] :since Time filters out any notifications
      #   updated before the given time. The time should be passed in as UTC in
      #   the ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ. Ex. '2012-10-09T23:39:01Z'
      # @return [Array<Sawyer::Resource>] Array of notifications.
      # @see https://developer.github.com/v3/activity/notifications/#list-your-notifications-in-a-repository
      # @example Get your notifications for octokit/octokit.rb
      #   @client.repository_notifications('octokit/octokit.rb')
      # @example Get your notifications for octokit/octokit.rb since a time.
      #   @client.repository_notifications({since: '2012-10-09T23:39:01Z'})
      def repository_notifications(repo, options = {})
        paginate "#{Repository.path repo}/notifications", options
      end
      alias :repo_notifications :repository_notifications

      # Mark notifications as read
      #
      # @param options [Hash] Optional parameters
      # @option options [Boolean] :unread Changes the unread status of the
      #   threads.
      # @option options [Boolean] :read Inverse of 'unread'.
      # @option options [String] :last_read_at ('Now') Describes the last point
      #   that notifications were checked. Anything updated since this time
      #   will not be updated. The time should be passed in as UTC in the
      #   ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ. Ex. '2012-10-09T23:39:01Z'
      # @return [Boolean] True if marked as read, false otherwise
      # @see https://developer.github.com/v3/activity/notifications/#mark-as-read
      #
      # @example
      #   @client.mark_notifications_as_read
      def mark_notifications_as_read(options = {})
        request :put, "notifications", options

        last_response.status == 205
      end

      # Mark notifications from a specific repository as read
      #
      # @param repo [Integer, String, Hash, Repository] A GitHub repository
      # @param options [Hash] Optional parameters
      # @option options [Boolean] :unread Changes the unread status of the
      #   threads.
      # @option options [Boolean] :read Inverse of 'unread'.
      # @option options [String] :last_read_at ('Now') Describes the last point
      #   that notifications were checked. Anything updated since this time
      #   will not be updated. The time should be passed in as UTC in the
      #   ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ. Ex. '2012-10-09T23:39:01Z'
      # @return [Boolean] True if marked as read, false otherwise
      # @see https://developer.github.com/v3/activity/notifications/#mark-notifications-as-read-in-a-repository
      # @example
      #   @client.mark_notifications_as_read("octokit/octokit.rb")
      def mark_repository_notifications_as_read(repo, options = {})
        request :put, "#{Repository.path repo}/notifications", options

        last_response.status == 205
      end
      alias :mark_repo_notifications_as_read :mark_repository_notifications_as_read

      # List notifications for a specific thread
      #
      # @param thread_id [Integer] Id of the thread.
      # @return [Array<Sawyer::Resource>] Array of notifications.
      # @see https://developer.github.com/v3/activity/notifications/#view-a-single-thread
      #
      # @example
      #   @client.notification_thread(1000)
      def thread_notifications(thread_id, options = {})
        get "notifications/threads/#{thread_id}", options
      end

      # Mark thread as read
      #
      # @param thread_id [Integer] Id of the thread to update.
      # @return [Boolean] True if updated, false otherwise.
      # @see https://developer.github.com/v3/activity/notifications/#mark-a-thread-as-read
      # @example
      #   @client.mark_thread_as_read(1, :read => false)
      def mark_thread_as_read(thread_id, options = {})
        request :patch, "notifications/threads/#{thread_id}", options

        last_response.status == 205
      end

      # Get thread subscription
      #
      # @param thread_id [Integer] Id of the thread.
      # @return [Sawyer::Resource] Subscription.
      # @see https://developer.github.com/v3/activity/notifications/#get-a-thread-subscription
      # @example
      #   @client.thread_subscription(1)
      def thread_subscription(thread_id, options = {})
        get "notifications/threads/#{thread_id}/subscription", options
      end

      # Update thread subscription
      #
      # This lets you subscribe to a thread, or ignore it. Subscribing to a
      # thread is unnecessary if the user is already subscribed to the
      # repository. Ignoring a thread will mute all future notifications (until
      # you comment or get @mentioned).
      #
      # @param thread_id [Integer] Id of the thread.
      # @param options
      # @option options [Boolean] :subscribed Determines if notifications
      #   should be received from this repository.
      # @option options [Boolean] :ignored Deterimines if all notifications
      #   should be blocked from this repository.
      # @return [Sawyer::Resource] Updated subscription.
      # @see https://developer.github.com/v3/activity/notifications/#set-a-thread-subscription
      # @example Subscribe to notifications
      #   @client.update_thread_subscription(1, :subscribed => true)
      # @example Ignore notifications from a repo
      #   @client.update_thread_subscription(1, :ignored => true)
      def update_thread_subscription(thread_id, options = {})
        put "notifications/threads/#{thread_id}/subscription", options
      end

      # Delete a thread subscription
      #
      # @param thread_id [Integer] Id of the thread.
      # @return [Boolean] True if delete successful, false otherwise.
      # @see https://developer.github.com/v3/activity/notifications/#delete-a-thread-subscription
      # @example
      #   @client.delete_thread_subscription(1)
      def delete_thread_subscription(thread_id, options = {})
        boolean_from_response :delete, "notifications/threads/#{thread_id}/subscription", options
      end
    end
  end
end
