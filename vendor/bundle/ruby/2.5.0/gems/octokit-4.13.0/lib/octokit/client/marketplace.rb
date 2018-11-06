module Octokit
  class Client

    # Methods for the Marketplace Listing API
    #
    # @see https://developer.github.com/v3/apps/marketplace/
    module Marketplace

      # List all plans for an app's marketplace listing
      #
      # @param options [Hash] A customizable set of options
      #
      # @see https://developer.github.com/v3/apps/marketplace/#list-all-plans-for-your-marketplace-listing
      #
      # @return [Array<Sawyer::Resource>] A list of plans
      def list_plans(options = {})
        paginate "/marketplace_listing/plans", options
      end

      # List all GitHub accounts on a specific plan
      #
      # @param plan_id [Integer] The id of the GitHub plan
      # @param options [Hash] A customizable set of options
      #
      # @see https://developer.github.com/v3/apps/marketplace/#list-all-github-accounts-user-or-organization-on-a-specific-plan
      #
      # @return [Array<Sawyer::Resource>] A list of accounts
      def list_accounts_for_plan(plan_id, options = {})
        paginate "/marketplace_listing/plans/#{plan_id}/accounts", options
      end

      # Get the plan associated with a given GitHub account
      #
      # @param account_id [Integer] The id of the GitHub account
      # @param options [Hash] A customizable set of options
      #
      # @see https://developer.github.com/v3/apps/marketplace/#check-if-a-github-account-is-associated-with-any-marketplace-listing
      #
      # @return <Sawyer::Resource> Account with plan details, or nil
      def plan_for_account(account_id, options = {})
        get "/marketplace_listing/accounts/#{account_id}", options
      end

      # Get user's Marketplace purchases
      #
      # @param options [Hash] A customizable set of options
      #
      # @see https://developer.github.com/v3/apps/marketplace/#get-a-users-marketplace-purchases
      #
      # @return [Array<Sawyer::Resource>] A list of Marketplace purchases
      def marketplace_purchases(options = {})
        get "/user/marketplace_purchases", options
      end
    end
  end
end
