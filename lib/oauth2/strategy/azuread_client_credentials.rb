require 'oauth2'

module OAuth2
  module Strategy
    # OAuth2::StrategyClientCredentials extensional class
    class AzureADClientCredentials < ClientCredentials

      def adminconsent_params(params = {})
        params.merge('client_id' => @client.id)
      end

      # for Azure AD
      def adminconsent_url(params = {})
        @client.adminconsent_url(adminconsent_params.merge(params))
      end
    end
  end
end
