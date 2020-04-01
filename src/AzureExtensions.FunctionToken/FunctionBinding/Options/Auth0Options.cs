using System;
using System.Linq;
using System.Threading;
using AzureExtensions.FunctionToken.FunctionBinding.Options.Interface;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AzureExtensions.FunctionToken.FunctionBinding.Options
{
    public sealed class Auth0Options : ITokenOptions
    {
        private static string scheme = "https";
        private static int port = 443;
        private static string openIdConfigurationPath = "/.well-known/openid-configuration";
        public TokenSigningKeyOptions SigningOptions { get; }

        public Auth0Options(string hostName, string audience)
            : this(
                new ConfigurationManager<OpenIdConnectConfiguration>(
                    new UriBuilder(scheme, hostName, port, openIdConfigurationPath).Uri.AbsoluteUri,
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
