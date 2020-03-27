using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using AzureExtensions.FunctionToken.FunctionBinding.Options.Interface;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AzureExtensions.FunctionToken.FunctionBinding.Options
{
    public sealed class Auth0Options : ITokenOptions
    {
        public TokenSigningKeyOptions SigningOptions { get; }

        public Auth0Options(string tenantName, string audience)
            : this(
                new ConfigurationManager<OpenIdConnectConfiguration>(
                    $"https://{tenantName}.auth0.com/.well-known/openid-configuration",
                    new OpenIdConnectConfigurationRetriever()
                ),
                audience
            )
        {
        }
        
        public Auth0Options(IConfigurationManager<OpenIdConnectConfiguration> configurationManager, string audience)
        {
            OpenIdConnectConfiguration config = configurationManager
                .GetConfigurationAsync(new CancellationTokenSource().Token)
                .GetAwaiter()
                .GetResult();
            
            SigningOptions = new TokenSigningKeyOptions()
            {
                SigningKey = config.JsonWebKeySet.Keys.FirstOrDefault(),
                Issuer = config.Issuer,
                Audience = audience,
            };
        }
    }
}
