using System;
using System.Security.AccessControl;
using System.Security.Authentication;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace AzureExtensions.FunctionToken
{
    public class Handler
    {
        /// <summary>
        /// Catches AuthenticationException and returns UnauthorizedResult, otherwise BadRequestObjectResult. 
        /// </summary>
        public static async Task<IActionResult> WrapAsync(FunctionTokenResult token, Func<Task<IActionResult>> action)
        {
            return await WrapAsync(null, token, action);
        }

        public static async Task<IActionResult> WrapAsync(ILogger logger, FunctionTokenResult token, Func<Task<IActionResult>> action)
        {
            try
            {
                token.ValidateThrow();
                var result = await action();
                return result;
            }
            catch (AuthenticationException)
            {
                return new UnauthorizedResult();
            }
            catch (PrivilegeNotHeldException)
            {
                var r = new ForbidResult("Bearer");
                return r;
            }
            catch (SecurityTokenExpiredException ex)
            {
                return new BadRequestObjectResult($"Authentication token expired at {ex.Expires}, current time is {DateTime.Now}. Acquire a new token to access this endpoint.");
            }
            catch (Exception ex)
            {
                logger?.LogError(ex.Message, ex);
                return new BadRequestObjectResult("Provide a valid [Bearer ******] token in the 'Authorization' header of your request. If you don't have a token yet, use the Insomnia templates or enable the Mocking feature in the API reference documentation.");
            }
        }

        /// <summary>
        /// Catches AuthenticationException and returns UnauthorizedResult, otherwise BadRequestObjectResult. 
        /// </summary>
        public static IActionResult Wrap(FunctionTokenResult token, Func<IActionResult> action)
        {
            try
            {
                token.ValidateThrow();
                var result = action();
                return result;
            }
            catch (AuthenticationException)
            {
                return new UnauthorizedResult();
            }
            catch (PrivilegeNotHeldException)
            {
                var r = new ForbidResult("Bearer");
                return r;
            }
            catch (SecurityTokenExpiredException ex)
            {
                return new BadRequestObjectResult($"Authentication token expired at {ex.Expires}, current time is {DateTime.Now}. Acquire a new token to access this endpoint.");
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult(ex.Message);
            }
        }
    }
}
