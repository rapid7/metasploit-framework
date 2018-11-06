module Octokit
  class Client

    # Methods for the Deployments API
    #
    # @see https://developer.github.com/v3/repos/commits/deployments/
    module Deployments

      # Fetch a single deployment for a repository
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param deployment_id [Integer, String, Repository, Hash] A GitHub repository
      # @return <Sawyer::Resource> A single deployment
      # @see https://developer.github.com/v3/repos/deployments/#get-a-single-deployment
      def deployment(repo, deployment_id, options = {})
        get("#{Repository.path repo}/deployments/#{deployment_id}", options)
      end

      # List all deployments for a repository
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @return [Array<Sawyer::Resource>] A list of deployments
      # @see https://developer.github.com/v3/repos/deployments/#list-deployments
      def deployments(repo, options = {})
        get("#{Repository.path repo}/deployments", options)
      end
      alias :list_deployments :deployments

      # Create a deployment for a ref
      #
      # @param repo [Integer, String, Repository, Hash] A GitHub repository
      # @param ref [String] The ref to deploy
      # @option options [String] :task Used by the deployment system to allow different execution paths. Defaults to "deploy".
      # @option options [String] :payload Meta info about the deployment
      # @option options [Boolean] :auto_merge Optional parameter to merge the default branch into the requested deployment branch if necessary. Default: true
      # @option options [Array<String>] :required_contexts Optional array of status contexts verified against commit status checks.
      # @option options [String] :environment Optional name for the target deployment environment (e.g., production, staging, qa). Default: "production"
      # @option options [String] :description Optional short description.
      # @return [Sawyer::Resource] A deployment
      # @see https://developer.github.com/v3/repos/deployments/#create-a-deployment
      def create_deployment(repo, ref, options = {})
        options[:ref] = ref
        post("#{Repository.path repo}/deployments", options)
      end

      # List all statuses for a Deployment
      #
      # @param deployment_url [String] A URL for a deployment resource
      # @return [Array<Sawyer::Resource>] A list of deployment statuses
      # @see https://developer.github.com/v3/repos/deployments/#list-deployment-statuses
      def deployment_statuses(deployment_url, options = {})
        deployment = get(deployment_url, :accept => options[:accept])
        get(deployment.rels[:statuses].href, options)
      end
      alias :list_deployment_statuses :deployment_statuses

      # Create a deployment status for a Deployment
      #
      # @param deployment_url [String] A URL for a deployment resource
      # @param state [String] The state: pending, success, failure, error
      # @option options [String] :target_url The target URL to associate with this status. Default: ""
      # @option options [String] :description A short description of the status. Maximum length of 140 characters. Default: ""
      # @return [Sawyer::Resource] A deployment status
      # @see https://developer.github.com/v3/repos/deployments/#create-a-deployment-status
      def create_deployment_status(deployment_url, state, options = {})
        deployment = get(deployment_url, :accept => options[:accept])
        options[:state] = state.to_s.downcase
        post(deployment.rels[:statuses].href, options)
      end
    end
  end
end
