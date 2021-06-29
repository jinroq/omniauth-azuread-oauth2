require "oauth2"
require "oauth2/strategy/azuread_client_credentials"


module OAuth2
  # OAuth2::Client extensional class
  class ClientExt < Client
    # for Azure AD
    def adminconsent_url(params = {})
      params = (params || {}).merge(redirection_params)
      connection.build_url(options[:adminconsent_url], params).to_s
    end

    def azuread_client_credentials
      @client ||= OAuth2::Strategy::AzureADClientCredentials.new(self)
    end
  end
end
