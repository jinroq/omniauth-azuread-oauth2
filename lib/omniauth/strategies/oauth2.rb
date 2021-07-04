require "omniauth"
require "oauth2/azuread_client"

require "socket"  # for SocketError
require "timeout" # for Timeout::Error

module OmniAuth
  module Strategies
    class OAuth2
      include OmniAuth::Strategy

      BASE_MSONLINE_URL = 'https://login.microsoftonline.com'.freeze
      BASE_MSGRAPH_URL  = 'https://graph.microsoft.com/v1.0'.freeze
      DEFAULT_SCOPE     = 'openid email profile User.Read'.freeze

      attr_accessor :access_token

      args %i[client_id client_secret]

      option :client_id,      nil
      option :client_secret,  nil
      option :tenant_id,      nil
      option :client_options, { site: BASE_MSONLINE_URL, adminconsent_url: '/common/v2.0/adminconsent' }
      # AzureAD account types:
      #   'single'   => Accounts in single organizational directory only
      #   'multiple' => Accounts in any organizational directory
      #   'complex'  => Accounts in any organizational directory and personal Microsoft accounts
      option :azuread_account_type, 'complex'

      # Grant types:
      #   'client_credentials'
      #   'authorization_code'
      option :grant_type,          'client_credentials'
      option :adminconsent_params, {}
      option :adminconsent_options, %i[scope state]

      # @see https://docs.microsoft.com/en-us/graph/query-parameters#select-parameter
      # @see https://docs.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0#common-properties
      option :select_properties, 'id,displayName,mail'

      # Defining the Request Phase
      # @see https://github.com/omniauth/omniauth/wiki/strategy-contribution-guide#defining-the-request-phase
      def request_phase
        if options.grant_type == 'client_credentials'
          redirect client.azuread_client_credentials.adminconsent_url({redirect_uri: callback_url}.merge(adminconsent_params))
        #elsif options.grant_type == 'authorization_code'
        #  redirect client.auth_code.authorize_url({:redirect_uri => callback_url}.merge(authorize_params))
        else
          raise 'error'
        end
      end

      # Defining the Callback Phase
      # @see https://github.com/omniauth/omniauth/wiki/strategy-contribution-guide#defining-the-callback-phase
      def callback_phase
        error = request.params['error_reason'] || request.params['error']

        if options.grant_type == 'client_credentials'
          self.access_token = client.azuread_client_credentials.get_token(
            { 'client_id'     => options.client_id,
              'client_secret' => options.client_secret,
              'scope'         => 'https://graph.microsoft.com/.default',
            }
          )
        #elsif options.grant_type == 'authorization_code'
        #  verifier = request.params["code"]
        #  client.auth_code.get_token(verifier,
        #                             {redirect_uri: callback_url}.merge(token_params.to_hash(symbolize_keys: true)),
        #                             deep_symbolize(options.auth_token_params))
        #  self.access_token = access_token.refresh! if access_token.expired?
        else
          raise 'error'
        end
      rescue ::OAuth2::Error, CallbackError => e
        fail!(:invalid_credentials, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

      def client
        if options.client_options.token_url.nil?
          if options.azuread_account_type == 'complex'
            options.client_options.token_url = '/common/oauth2/v2.0/token'
          elsif options.azuread_account_type == 'multiple'
            target_tenant_id = request.params["tenant"]
            options.client_options.token_url = "/#{target_tenant_id}/oauth2/v2.0/token"
          elsif options.azuread_account_type == 'single'
            raise 'error' unless options.tenant_id
            options.client_options.token_url = "/#{options.tenant_id}/oauth2/v2.0/token"
          else
            raise 'error'
          end
        end

        ::OAuth2::AzureADClient.new(options.client_id,
                                    options.client_secret,
                                    deep_symbolize(options.client_options))
      end

      def adminconsent_params
        options.adminconsent_params[:state] = SecureRandom.hex(24)

        if OmniAuth.config.test_mode
          @env ||= {}
          @env["rack.session"] ||= {}
        end

        options.adminconsent_params.merge(options_for('adminconsent'))
      end

      uid { raw_info['id'] }

      info do
        { name:  raw_info['displayName'],
          email: raw_info['mail'],
        }
      end

      credentials do
        hash = { 'token' => access_token.token }
        if access_token.expires?
          hash['refresh_token'] = access_token.refresh_token if access_token.refresh_token
          hash['expires_at'] = access_token.expires_at 
        end
        hash['expires'] = access_token.expires?
        hash
      end

      extra { 'raw_info' => raw_info }

      def raw_info
        @raw_info ||= access_token.get("#{BASE_MSGRAPH_URL}/me?$select=#{options.select_properties}").parsed
      end

      # @override
      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      protected

      def deep_symbolize(options)
        options.each_with_object({}) do |(key, value), hash|
          hash[key.to_sym] = value.is_a?(Hash) ? deep_symbolize(value) : value
        end
      end

      def options_for(option)
        hash = {}
        options.send(:"#{option}_options").select { |key| options[key] }.each do |key|
          hash[key.to_sym] = if options[key].respond_to?(:call)
                               options[key].call(env)
                             else
                               options[key]
                             end
        end
        hash
      end

      # An error that is indicated in the OAuth 2.0 callback.
      # This could be a `redirect_uri_mismatch` or other
      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(error, error_reason = nil, error_uri = nil)
          self.error = error
          self.error_reason = error_reason
          self.error_uri = error_uri
        end

        def message
          [error, error_reason, error_uri].compact.join(" | ")
        end
      end

    end
  end
end

OmniAuth.config.add_camelization "oauth2", "OAuth2"
