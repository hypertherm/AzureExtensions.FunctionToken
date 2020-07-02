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
            bool anyScopeMatch = false;
            // if any scopes are present check them
            if (InputAttribute.Scopes != null && InputAttribute.Scopes.Length > 0)
            {
                // Check each of the scopes
                foreach(string scope in InputAttribute.Scopes)
                {
                    // Currently only support OR
                    anyScopeMatch |= claimsPrincipal.IsInScope(scope, ScopeClaimNameFromPrincipal);
                }
            }
            else // no scopes are present
            {
                // This is true by default
                anyScopeMatch = true;
            }

            // Combine the scope and role requirements
            return anyScopeMatch && claimsPrincipal.IsInRole(InputAttribute.Roles);
        }
    }
}