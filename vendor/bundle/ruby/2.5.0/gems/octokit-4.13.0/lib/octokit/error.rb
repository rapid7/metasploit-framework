module Octokit
  # Custom error class for rescuing from all GitHub errors
  class Error < StandardError

    # Returns the appropriate Octokit::Error subclass based
    # on status and response message
    #
    # @param [Hash] response HTTP response
    # @return [Octokit::Error]
    def self.from_response(response)
      status  = response[:status].to_i
      body    = response[:body].to_s
      headers = response[:response_headers]

      if klass =  case status
                  when 400      then Octokit::BadRequest
                  when 401      then error_for_401(headers)
                  when 403      then error_for_403(body)
                  when 404      then error_for_404(body)
                  when 405      then Octokit::MethodNotAllowed
                  when 406      then Octokit::NotAcceptable
                  when 409      then Octokit::Conflict
                  when 415      then Octokit::UnsupportedMediaType
                  when 422      then Octokit::UnprocessableEntity
                  when 451      then Octokit::UnavailableForLegalReasons
                  when 400..499 then Octokit::ClientError
                  when 500      then Octokit::InternalServerError
                  when 501      then Octokit::NotImplemented
                  when 502      then Octokit::BadGateway
                  when 503      then Octokit::ServiceUnavailable
                  when 500..599 then Octokit::ServerError
                  end
        klass.new(response)
      end
    end

    def initialize(response=nil)
      @response = response
      super(build_error_message)
    end

    # Documentation URL returned by the API for some errors
    #
    # @return [String]
    def documentation_url
      data[:documentation_url] if data.is_a? Hash
    end

    # Returns most appropriate error for 401 HTTP status code
    # @private
    def self.error_for_401(headers)
      if Octokit::OneTimePasswordRequired.required_header(headers)
        Octokit::OneTimePasswordRequired
      else
        Octokit::Unauthorized
      end
    end

    # Returns most appropriate error for 403 HTTP status code
    # @private
    def self.error_for_403(body)
      if body =~ /rate limit exceeded/i
        Octokit::TooManyRequests
      elsif body =~ /login attempts exceeded/i
        Octokit::TooManyLoginAttempts
      elsif body =~ /abuse/i
        Octokit::AbuseDetected
      elsif body =~ /repository access blocked/i
        Octokit::RepositoryUnavailable
      elsif body =~ /email address must be verified/i
        Octokit::UnverifiedEmail
      elsif body =~ /account was suspended/i
        Octokit::AccountSuspended
      else
        Octokit::Forbidden
      end
    end

    # Return most appropriate error for 404 HTTP status code
    # @private
    def self.error_for_404(body)
      if body =~ /Branch not protected/i
        Octokit::BranchNotProtected
      else
        Octokit::NotFound
      end
    end

    # Array of validation errors
    # @return [Array<Hash>] Error info
    def errors
      if data && data.is_a?(Hash)
        data[:errors] || []
      else
        []
      end
    end

    # Status code returned by the GitHub server.
    #
    # @return [Integer]
    def response_status
      @response[:status]
    end

    # Headers returned by the GitHub server.
    #
    # @return [Hash]
    def response_headers
      @response[:response_headers]
    end

    # Body returned by the GitHub server.
    #
    # @return [String]
    def response_body
      @response[:body]
    end

    private

    def data
      @data ||=
        if (body = @response[:body]) && !body.empty?
          if body.is_a?(String) &&
            @response[:response_headers] &&
            @response[:response_headers][:content_type] =~ /json/

            Sawyer::Agent.serializer.decode(body)
          else
            body
          end
        else
          nil
        end
    end

    def response_message
      case data
      when Hash
        data[:message]
      when String
        data
      end
    end

    def response_error
      "Error: #{data[:error]}" if data.is_a?(Hash) && data[:error]
    end

    def response_error_summary
      return nil unless data.is_a?(Hash) && !Array(data[:errors]).empty?

      summary = "\nError summary:\n"
      summary << data[:errors].map do |error|
        if error.is_a? Hash
          error.map { |k,v| "  #{k}: #{v}" }
        else
          "  #{error}"
        end
      end.join("\n")

      summary
    end

    def build_error_message
      return nil if @response.nil?

      message =  "#{@response[:method].to_s.upcase} "
      message << redact_url(@response[:url].to_s) + ": "
      message << "#{@response[:status]} - "
      message << "#{response_message}" unless response_message.nil?
      message << "#{response_error}" unless response_error.nil?
      message << "#{response_error_summary}" unless response_error_summary.nil?
      message << " // See: #{documentation_url}" unless documentation_url.nil?
      message
    end

    def redact_url(url_string)
      %w[client_secret access_token].each do |token|
        url_string.gsub!(/#{token}=\S+/, "#{token}=(redacted)") if url_string.include? token
      end
      url_string
    end
  end

  # Raised on errors in the 400-499 range
  class ClientError < Error; end

  # Raised when GitHub returns a 400 HTTP status code
  class BadRequest < ClientError; end

  # Raised when GitHub returns a 401 HTTP status code
  class Unauthorized < ClientError; end

  # Raised when GitHub returns a 401 HTTP status code
  # and headers include "X-GitHub-OTP"
  class OneTimePasswordRequired < ClientError
    #@private
    OTP_DELIVERY_PATTERN = /required; (\w+)/i

    #@private
    def self.required_header(headers)
      OTP_DELIVERY_PATTERN.match headers['X-GitHub-OTP'].to_s
    end

    # Delivery method for the user's OTP
    #
    # @return [String]
    def password_delivery
      @password_delivery ||= delivery_method_from_header
    end

    private

    def delivery_method_from_header
      if match = self.class.required_header(@response[:response_headers])
        match[1]
      end
    end
  end

  # Raised when GitHub returns a 403 HTTP status code
  class Forbidden < ClientError; end

  # Raised when GitHub returns a 403 HTTP status code
  # and body matches 'rate limit exceeded'
  class TooManyRequests < Forbidden; end

  # Raised when GitHub returns a 403 HTTP status code
  # and body matches 'login attempts exceeded'
  class TooManyLoginAttempts < Forbidden; end

  # Raised when GitHub returns a 403 HTTP status code
  # and body matches 'abuse'
  class AbuseDetected < Forbidden; end

  # Raised when GitHub returns a 403 HTTP status code
  # and body matches 'repository access blocked'
  class RepositoryUnavailable < Forbidden; end

  # Raised when GitHub returns a 403 HTTP status code
  # and body matches 'email address must be verified'
  class UnverifiedEmail < Forbidden; end

  # Raised when GitHub returns a 403 HTTP status code
  # and body matches 'account was suspended'
  class AccountSuspended < Forbidden; end

  # Raised when GitHub returns a 404 HTTP status code
  class NotFound < ClientError; end

  # Raised when GitHub returns a 404 HTTP status code
  # and body matches 'Branch not protected'
  class BranchNotProtected < ClientError; end

  # Raised when GitHub returns a 405 HTTP status code
  class MethodNotAllowed < ClientError; end

  # Raised when GitHub returns a 406 HTTP status code
  class NotAcceptable < ClientError; end

  # Raised when GitHub returns a 409 HTTP status code
  class Conflict < ClientError; end

  # Raised when GitHub returns a 414 HTTP status code
  class UnsupportedMediaType < ClientError; end

  # Raised when GitHub returns a 422 HTTP status code
  class UnprocessableEntity < ClientError; end

  # Raised when GitHub returns a 451 HTTP status code
  class UnavailableForLegalReasons < ClientError; end

  # Raised on errors in the 500-599 range
  class ServerError < Error; end

  # Raised when GitHub returns a 500 HTTP status code
  class InternalServerError < ServerError; end

  # Raised when GitHub returns a 501 HTTP status code
  class NotImplemented < ServerError; end

  # Raised when GitHub returns a 502 HTTP status code
  class BadGateway < ServerError; end

  # Raised when GitHub returns a 503 HTTP status code
  class ServiceUnavailable < ServerError; end

  # Raised when client fails to provide valid Content-Type
  class MissingContentType < ArgumentError; end

  # Raised when a method requires an application client_id
  # and secret but none is provided
  class ApplicationCredentialsRequired < StandardError; end

  # Raised when a repository is created with an invalid format
  class InvalidRepository < ArgumentError; end

end
