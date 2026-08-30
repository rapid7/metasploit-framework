# frozen_string_literal: true
module Metasploit
  module Framework
    module DataService
      module Remote
        class HttpError < StandardError
          def initialize(error:, status_code:, message: 'Unknown Error')
            super(message)
            @error = error
            @status_code = status_code
          end

          attr_reader :error, :status_code
        end

        class ServerError < HttpError
          def initialize(error:, status_code: 500, message: 'Internal Server Error')
            super
          end
        end

        class ClientError < HttpError
          def initialize(error:, status_code: 400, message: 'Client Error')
            super
          end
        end

        class NotFound < HttpError
          def initialize(error:, status_code: 404, message: 'Not Found')
            super
          end
        end
      end
    end
  end
end
