using System.Collections;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AzureExtensions.FunctionToken.FunctionBinding.Enums;
using AzureExtensions.FunctionToken.FunctionBinding.Options;
using AzureExtensions.FunctionToken.FunctionBinding.TokenProviders.Auth0;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;

namespace AzureExtensions.FunctionToken.Tests
{
    public class Auth0ValueProviderTests
    {
        [Theory]
        [ClassData(typeof(UnitsTestData))]
        public void GetValueAsyncWorksForScope(string[] requiredScopes, string[] authorizedRoles, List<Claim> claims, TokenStatus tokenStatus)
        {
            Mock<HttpRequest> request = new Mock<HttpRequest>();
            request
                .SetupGet(r => r.Headers)
                .Returns(new HeaderDictionary { { "Authorization", "Bearer abc123" } });
            request
                .SetupGet(r => r.HttpContext)
                .Returns(Mock.Of<HttpContext>());
            Mock<IConfigurationManager<OpenIdConnectConfiguration>> mockConfigurationManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
            mockConfigurationManager
                .Setup(c => c.GetConfigurationAsync(It.IsAny<CancellationToken>()))
                .Returns(
                    Task.FromResult( 
                        new OpenIdConnectConfiguration
                        {
                            JsonWebKeySet = new JsonWebKeySet(
@"{
    ""keys"": [
        {
            ""alg"": ""RS256"",
            ""kty"": ""RSA"",
            ""use"": ""sig"",
            ""n"": ""big string1"",
            ""e"": ""AQAB"",
            ""kid"": ""big string 2"",
            ""x5t"": ""big string 2"",
            ""x5c"": [
                ""big string 3""
            ]
        }
    ]
}"
                            )
                        }
                    )
                );
            Auth0Options options = new Auth0Options(mockConfigurationManager.Object, "someaudience");

            FunctionTokenAttribute attribute = new FunctionTokenAttribute(
                AuthLevel.Authorized,
                requiredScopes,
                authorizedRoles
            );
            SecurityToken mockSecurityToken = Mock.Of<SecurityToken>();
            Mock<ISecurityTokenValidator> mockSecurityTokenValidator = new Mock<ISecurityTokenValidator>();
            mockSecurityTokenValidator
                .Setup(v => v.ValidateToken(
                        It.IsAny<string>(),
                        It.IsAny<TokenValidationParameters>(),
                        out mockSecurityToken
                    )
                )
                .Returns(
                    new ClaimsPrincipal(
                        new List<ClaimsIdentity> {
                            new ClaimsIdentity(
                                claims, 
                                "Bearer"
                            )
                    })
                );

            Auth0ValueProvider provider = new Auth0ValueProvider(
                request.Object,
                options,
                attribute,
                mockSecurityTokenValidator.Object
            );
            
            ((FunctionTokenResult) (provider
                .GetValueAsync()
                .GetAwaiter()
                .GetResult()))
                .Status
                .Should()
                .Be(tokenStatus);
        }

        public class UnitsTestData: IEnumerable<object[]>
        {
            public IEnumerator<object[]> GetEnumerator()
            {
                // No Scopes or Roles Required on Function
                
                yield return new object[] {
                    null,
                    null,
                    new List<Claim>(),
                    TokenStatus.Valid
                };
                
                yield return new object[] {
                    null,
                    new string[] {},
                    new List<Claim>(),
                    TokenStatus.Valid
                };

                yield return new object[] {
                    new string[] {},
                    new string[] {},
                    new List<Claim>(),
                    TokenStatus.Valid
                };
                yield return new object[] {
                    new string[] {""},
                    new string[] {},
                    new List<Claim>(),
                    TokenStatus.Valid
                };

                yield return new object[] {
                    new string[] {""},
                    null,
                    new List<Claim>(),
                    TokenStatus.Valid
                };

                // Only  scope is required
                yield return new object[] {
                    new string[] {"read"},
                    null,
                    new List<Claim> 
                    {
                        new Claim("scope", "Read"),
                    },
                    TokenStatus.Valid
                };
                
                yield return new object[] {
                    new string[] {"read", "extra"},
                    null,
                    new List<Claim> 
                    {
                        new Claim("scope", "Read"),
                    },
                    TokenStatus.Valid
                };

                yield return new object[] {
                    new string[] { "read" },
                    new string[] {},
                    new List<Claim> 
                    {
                        new Claim("scope", "Read"),
                    },
                    TokenStatus.Valid
                };

                yield return new object[] {
                    new string[] { "read", "extra" },
                    new string[] {},
                    new List<Claim> 
                    {
                        new Claim("scope", "Read"),
                    },
                    TokenStatus.Valid
                };

                yield return new object[] {
                    new string[] { "extra1", "read", "extra2" },
                    new string[] {},
                    new List<Claim> 
                    {
                        new Claim("scope", "Read"),
                    },
                    TokenStatus.Valid
                };

                yield return new object[] {
                    new string[] { "read" },
                    new string[] {},
                    new List<Claim> 
                    {
                        new Claim("scope", "Different Scope"),
                    },
                    TokenStatus.Error
                };

                yield return new object[] {
                    new string[] { "read" },
                    null,
                    new List<Claim> 
                    {
                        new Claim("scope", "Different Scope"),
                    },
                    TokenStatus.Error
                };
                
                yield return new object[] {
                    new string[] { "read" },
                    null,
                    new List<Claim> (),
                    TokenStatus.Error
                };
                
                yield return new object[] {
                    new string[] { "read" },
                    new string[] {},
                    new List<Claim> (),
                    TokenStatus.Error
                };

                yield return new object[] {
                    new string[] { "read", "write"},
                    null,
                    new List<Claim> (),
                    TokenStatus.Error
                };
                
                yield return new object[] {
                    new string[] { "read", "write"},
                    new string[] {},
                    new List<Claim> (),
                    TokenStatus.Error
                };

                // Handle multiple scopes in returned claim
                yield return new object[] {
                    new string[] { "read" },
                    null,
                    new List<Claim> 
                    {
                        new Claim("scope", "write read"),
                    },
                    TokenStatus.Valid
                };

                yield return new object[] {
                    new string[] { "read" },
                    new string[] {},
                    new List<Claim> 
                    {
                        new Claim("scope", "write read"),
                    },
                    TokenStatus.Valid
                };
                
                yield return new object[] {
                    new string[] { "read", "write" },
                    null,
                    new List<Claim> 
                    {
                        new Claim("scope", "write read"),
                    },
                    TokenStatus.Valid
                };

                yield return new object[] {
                    new string[] { "read", "write" },
                    new string[] {},
                    new List<Claim> 
                    {
                        new Claim("scope", "write read"),
                    },
                    TokenStatus.Valid
                };
                // Scope and Role Required by function
                yield return new object[] {
                    new string[] { "read" },
                    new string[] {"user"},
                    new List<Claim> 
                    {
                        new Claim("scope", "read"),
                    },
                    TokenStatus.Error
                };

                yield return new object[] {
                    new string[] { "read" },
                    new string[] {"user"},
                    new List<Claim> 
                    {
                        new Claim("scope", "write read"),
                    },
                    TokenStatus.Error
                };
                
                yield return new object[] {
                    new string[] { "read", "write" },
                    new string[] {"user"},
                    new List<Claim> 
                    {
                        new Claim("scope", "read"),
                    },
                    TokenStatus.Error
                };

                yield return new object[] {
                    new string[] { "read", "write" },
                    new string[] {"user"},
                    new List<Claim> 
                    {
                        new Claim("scope", "write read"),
                    },
                    TokenStatus.Error
                };

                yield return new object[] {
                    new string[] { "read" },
                    new string[] {"user"},
                    new List<Claim> 
                    {
                        new Claim("scope", "read"),
                        new Claim(ClaimTypes.Role, "nonuser")
                    },
                    TokenStatus.Error
                };
                
                yield return new object[] {
                    new string[] { "read", "write" },
                    new string[] {"user"},
                    new List<Claim> 
                    {
                        new Claim("scope", "read"),
                        new Claim(ClaimTypes.Role, "nonuser")
                    },
                    TokenStatus.Error
                };
                yield return new object[] {
                    new string[] { "read", "write" },
                    new string[] {"user"},
                    new List<Claim> 
                    {
                        new Claim("scope", "read write"),
                        new Claim(ClaimTypes.Role, "nonuser")
                    },
                    TokenStatus.Error
                };

                yield return new object[] {
                    new string[] { "read" },
                    new string[] {"user"},
                    new List<Claim> 
                    {
                        new Claim("scope", "read"),
                        new Claim(ClaimTypes.Role, "user")
                    },
                    TokenStatus.Valid
                };

                yield return new object[] {
                    new string[] { "read" },
                    new string[] {"user"},
                    new List<Claim> 
                    {
                        new Claim("scope", "write read"),
                        new Claim(ClaimTypes.Role, "user")
                    },
                    TokenStatus.Valid
                };
                

                yield return new object[] {
                    new string[] { "read", "write" },
                    new string[] {"user"},
                    new List<Claim> 
                    {
                        new Claim("scope", "read"),
                        new Claim(ClaimTypes.Role, "user")
                    },
                    TokenStatus.Valid
                };

                yield return new object[] {
                    new string[] { "read", "write" },
                    new string[] {"user"},
                    new List<Claim> 
                    {
                        new Claim("scope", "write read"),
                        new Claim(ClaimTypes.Role, "user")
                    },
                    TokenStatus.Valid
                };
                yield return new object[] {
                    new string[] { "read" },
                    new string[] {"admin", "user"},
                    new List<Claim> 
                    {
                        new Claim("scope", "read"),
                        new Claim(ClaimTypes.Role, "user")
                    },
                    TokenStatus.Valid
                };
                yield return new object[] {
                    new string[] { "read", "write" },
                    new string[] {"admin", "user"},
                    new List<Claim> 
                    {
                        new Claim("scope", "read write"),
                        new Claim(ClaimTypes.Role, "user")
                    },
                    TokenStatus.Valid
                };
            }
            IEnumerator IEnumerable.GetEnumerator() => (IEnumerator) GetEnumerator();
        }
    }
}
