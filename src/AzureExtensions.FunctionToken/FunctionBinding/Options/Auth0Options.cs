using System.Linq;
using AzureExtensions.FunctionToken.FunctionBinding.Options.Interface;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace AzureExtensions.FunctionToken.FunctionBinding.Options
{
    public sealed class Auth0Options : ITokenOptions
    {
        public TokenSigningKeyOptions SigningOptions { get; }

        public Auth0Options(string audience)
        {
             ConfigurationManager<OpenIdConnectConfiguration> configManager =
                new ConfigurationManager<OpenIdConnectConfiguration>(
                    "https://dev-pxwhh3cr.auth0.com/.well-known/openid-configuration",
                    new OpenIdConnectConfigurationRetriever());

            OpenIdConnectConfiguration config = null;
            config = configManager.GetConfigurationAsync().GetAwaiter().GetResult();
            
            SigningOptions = new TokenSigningKeyOptions()
            {
                SigningKey = config.JsonWebKeySet.Keys.FirstOrDefault(),
                Issuer = config.Issuer,
                Audience = audience,
            };
        }
    }
}
