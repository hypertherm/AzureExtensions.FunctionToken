using System.Security.Claims;
using AzureExtensions.FunctionToken.FunctionBinding.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using AzureExtensions.FunctionToken.Extensions;
using AzureExtensions.FunctionToken.FunctionBinding.TokenProviders.SigningKey;

namespace AzureExtensions.FunctionToken.FunctionBinding.TokenProviders.Auth0
{
    /// <summary>
    /// Provides values loaded from Azure B2C.
    /// </summary>
    internal class Auth0ValueProvider : SigningKeyValueProvider
    {
        
        private const string ScopeClaimNameFromPrincipal = "scope";

        /// <inheritdoc />
        public Auth0ValueProvider(
            HttpRequest request,
            Auth0Options options,
            FunctionTokenAttribute attribute)
            : base(request, options.SigningOptions, attribute)
        {
        }

        public Auth0ValueProvider(
            HttpRequest request,
            Auth0Options options,
            FunctionTokenAttribute attribute,
            ISecurityTokenValidator securityHandler)
            : base(request, options.SigningOptions, attribute, securityHandler)
        {
        }

        protected override bool IsAuthorizedForAction(ClaimsPrincipal claimsPrincipal)
        {
            return claimsPrincipal.IsInScope(InputAttribute.ScopeRequired, ScopeClaimNameFromPrincipal)
                && claimsPrincipal.IsInRole(InputAttribute.Roles);
        }
    }
}