using System.Web;

namespace OpenId.AspNet.Authentication
{
    internal static class HttpContextExtensions
    {
        /// <summary>
        /// returns Base URL with trailing '/'
        /// </summary>
        /// <param name="httpContext">The HTTP context.</param>
        /// <returns></returns>
        public static string BaseUrl(this HttpContext httpContext)
        {
            var request = httpContext.Request;
            var appUrl = HttpRuntime.AppDomainAppVirtualPath;
            if(string.IsNullOrWhiteSpace(appUrl)) { appUrl = "/"; }
            else if(!appUrl.EndsWith("/")) { appUrl += "/"; }
            var baseUrl = $"{request.Url.Scheme}://{request.Url.Authority}{appUrl}";
            return baseUrl;
        }

    }
}
