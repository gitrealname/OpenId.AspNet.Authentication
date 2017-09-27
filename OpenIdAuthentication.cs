using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Routing;
using IdentityModel.Client;
using Microsoft.IdentityModel.Tokens;

namespace OpenId.AspNet.Authentication
{
    /// <summary>
    /// Integration of OpenId connect Authentication/Authorization with Asp.NET legacy applications.
    /// Also, provides OAuth2 protection for (integrated) exposed Ajax/WebApi endpoints/resources.
    /// </summary>
    public static class OpenIdAuthentication
    {
        internal static OpenIdConnectOptions Options;

        private static OpenIdService _idsService;

        private static TokenValidationService _tokenValidationService;

        /// <summary>
        /// Configures the Authentication layer.
        /// 
        /// </summary>
        /// <param name="options">The options.</param>
        public static void Configure(OpenIdConnectOptions options)
        {
            Options = options;
            Options.TrustedAuthoritiesSet = new HashSet<string>();
            if(options.TrustedAuthorities != null)
            {
                foreach(var auth in options.TrustedAuthorities)
                {
                    var key = auth.ToLowerInvariant().RemoveTrailingSlash();
                    Options.TrustedAuthoritiesSet.Add(key);
                }
            }
            Options.TrustedAuthoritiesSet.Add(Options.Authority.ToLowerInvariant().RemoveTrailingSlash());

            //convert endpoint prefixes into app relative virtual path
            if(options.DemandAuthorizationHeaderForEndpointPrefixes?.Count > 0)
            {
                var list = new List<string>();
                foreach(var p in options.DemandAuthorizationHeaderForEndpointPrefixes)
                {
                    list.Add(System.Web.VirtualPathUtility.ToAppRelative(p));
                }
            }

            _idsService = new OpenIdService(Options);

            _tokenValidationService = new TokenValidationService(_idsService);

            var routes = RouteTable.Routes;

            var openIdRouterHandler = new RouterHandler();

            //create fake routes for open id sign-in and sign out endpoint
            //NOTE: without '/{action}' Html.ActionLink helper goes crazy and build incorrect url 
            var routeSignIn = new Route(options.Authentication.SignInEndpoint + "/{action}", openIdRouterHandler) {
                Defaults = new RouteValueDictionary() { { "controller", options.Authentication.SignInEndpoint }, { "action", "Index" } }
            };
            var routeSignOutCallback = new Route(options.Authentication.SignOutCallbackEndpoint + "/{action}", openIdRouterHandler) {
                Defaults = new RouteValueDictionary() { { "controller", options.Authentication.SignOutCallbackEndpoint }, { "action", "Index" } }
            };
            routes.Add("OpenIdSignInEndpoint", routeSignIn);
            routes.Add("OpenIdSignOutCallbackEndpoint", routeSignOutCallback);
        }

        /// <summary>
        /// Starts the authentication flow.
        /// </summary>
        /// <param name="landingPageUrl">The landing page URL.</param>
        public static void StartAuthenticationFlow(string landingPageUrl = null)
        {
            StartAuthenticationFlowAsync().GetAwaiter().GetResult();
        }

        /// <summary>
        /// Starts the authentication flow asynchronous.
        /// </summary>
        /// <param name="landingPageUrl">The landing page URL.</param>
        /// <returns></returns>
        public static async Task StartAuthenticationFlowAsync(string landingPageUrl = null)
        {
            var httpContext = HttpContext.Current;
            var opts = Options;
            var tuple = await _idsService.GetDiscoveryResponseAsync(Options.Authority).ConfigureAwait(false);
            var disco = tuple.Item1;
            if(disco == null)
            {
                RedirectToError(httpContext, tuple.Item2, tuple.Item3);
                return;
            }
            //prepare response
            var response = httpContext.Response;
            response.Clear();
            var nonceCookie = new HttpCookie(Const.NonceCookieName);
            var stateCookie = new HttpCookie(Const.StateCookieName);
            nonceCookie.Value = Guid.NewGuid().ToString().ToBase64();
            nonceCookie.Expires = DateTime.Now.AddMinutes(20);
            nonceCookie.HttpOnly = true;
            stateCookie.Value = landingPageUrl ?? httpContext.Request.Url.AbsoluteUri.ToBase64();
            stateCookie.Expires = nonceCookie.Expires;
            stateCookie.HttpOnly = true;
            //set cookies
            response.Cookies.Add(nonceCookie);
            response.Cookies.Add(stateCookie);

            //prepare authorization url
            var uri = httpContext.Request.Url;
            var scope = "openid"
                    + (opts.Authentication.RequestRefreshKey ? " offline_access" : "")
                    + " " + string.Join(" ", opts.Authentication.ResourceList);
            var url = new AuthorizeRequest(disco.AuthorizeEndpoint).CreateAuthorizeUrl(
                clientId: opts.ClientId,
                responseType: "code id_token",
                responseMode: "form_post",
                redirectUri:  httpContext.BaseUrl() + opts.Authentication.SignInEndpoint,   //$"{uri.Scheme}://{uri.Authority}/{opts.Authentication.SignInEndpoint}",
                scope: scope,
                nonce: nonceCookie.Value,
                state: stateCookie.Value
            );

            response.Redirect(url);
        }

        internal static void RedirectToError(HttpContext httpContext, int errorCode, string errorMessage)
        {
            httpContext.Response.Redirect(Options.Authentication.ErrorUrl + $"?errorCode={errorCode}&errorMessage={errorMessage}");
        }

        /// <summary>
        /// Signs the in callback.
        /// </summary>
        /// <param name="httpContext">The HTTP context.</param>
        internal static void SignInCallback(HttpContext httpContext)
        {
            var request = httpContext.Request;
            var response = httpContext.Response;
            var opts = Options;
            if(request.HttpMethod != HttpMethod.Post.Method)
            {
                RedirectToError(httpContext, 2000, $"Unexpected HTTP method: {request.HttpMethod}.");
                return;
            }
            //parse response
            var content = new byte[request.ContentLength + 1];
            using(var stream = request.GetBufferedInputStream())
            {
                stream.Read(content, 0, request.ContentLength);
            }
            var contentString = Encoding.UTF8.GetString(content);
            var authResponse = new AuthorizeResponse(contentString);

            //read and remove cookies
            var stateCookie = request.Cookies.Get(Const.StateCookieName);
            var nonceCookie = request.Cookies.Get(Const.NonceCookieName);
            if(stateCookie != null)
            {
                stateCookie.Expires = DateTime.Now.AddDays(-1);
                response.Cookies.Set(stateCookie);
            }
            if(nonceCookie != null)
            {
                nonceCookie.Expires = DateTime.Now.AddDays(-1);
                response.Cookies.Set(nonceCookie);
            }

            //check for error
            if(authResponse.IsError)
            {
                RedirectToError(httpContext, 4000, $"Identity Server Response Error: {authResponse.Error}.");
                return;
            }

            //validate state
            if(stateCookie == null || !stateCookie.Value.Equals(authResponse.State))
            {
                RedirectToError(httpContext, 3000, $"Invalid state.");
                return;
            }


            //validate token
            var encodedToken = authResponse.IdentityToken;
            ClaimsPrincipal claimPrincipal;
            SecurityToken token;
            try
            {
                claimPrincipal = _tokenValidationService.ValidateIdToken(encodedToken, false, out token);
            }
            catch(Exception e)
            {
                RedirectToError(httpContext, 5000, e.Message.Replace("\n", " " ));
                return;
            }

            //validate nonce
            var nonce = claimPrincipal.FindFirst("nonce")?.Value ?? "";
            if(nonceCookie == null || !nonceCookie.Value.Equals(nonce))
            {
                RedirectToError(httpContext, 6000, $"Nonce mismatch.");
                return;
            }


            //set cookie
            var openIdAuthData = new AuthorizationData(authResponse, (JwtSecurityToken)token);
            SetAuthCookie(httpContext, openIdAuthData);

            //redirect
            var url = authResponse.State.FromBase64();
            response.Redirect(url);
        }

        private static void SetAuthCookie(HttpContext httpContext, AuthorizationData openIdAuthData)
        {
            var value = openIdAuthData.Encrypt();
            var chunks = value.Split(3900).ToArray(); //max single cookie size is 4096!
            for(var i = 0; i < chunks.Length; i++ )
            {
                var c = chunks[i];
                var suffix = i == 0 ? "" : "." + (i);
                var cookie = new HttpCookie(Const.AuthorizationCookieName + suffix) {
                    Expires = openIdAuthData.SecurityToken.ValidTo,
                    HttpOnly = true,
                    Value = c
                };
                httpContext.Response.Cookies.Set(cookie);
            }
        }

        /// <summary>
        /// Authenticates request.
        /// In case if both cookie and Authorization: Bearer header are present, Authorization will be performed using the Header!
        /// NOTE: typically, call to this method should be placed into 'Application_AuthenticateRequest' HttpApplication event handler.
        /// </summary>
        public static void Authenticate()
        {
            var httpContext = HttpContext.Current;
            if(httpContext.User != null && httpContext.User.Identity.IsAuthenticated)
            {
                return;
            }
            var request = httpContext.Request;
            var authHeader = request.Headers["Authorization"];
            if(authHeader != null)
            {
                AuthenticateWithHeader(httpContext, authHeader);
                return;
            }
            //ignore cookie if request goes to listed Ajax/WebApi endpoints
            if(Options.DemandAuthorizationHeaderForEndpointPrefixes?.Count > 0)
            {
                if(Options.DemandAuthorizationHeaderForEndpointPrefixes.Any(p => request.AppRelativeCurrentExecutionFilePath != null && request.AppRelativeCurrentExecutionFilePath.StartsWith(p)))
                {
                    return;
                }
            }

            //try to get auth cookie
            var cookie = request.Cookies.Get(Const.AuthorizationCookieName);
            if(cookie == null)
            {
                return;
            }
            var cookieValue = cookie == null ? "" : cookie.Value;
            HttpCookie chunkCookie;
            var i = 1;
            while((chunkCookie = request.Cookies.Get(Const.AuthorizationCookieName + "." + i)) != null)
            {
                cookieValue += chunkCookie.Value;
                i++;
            }
            //decrypt cookie and apply claim principal
            try
            {
                var openIdData = AuthorizationData.CreateFromEncryptedString(cookieValue);
                SecurityToken token;
                var claimPrincipal = _tokenValidationService.ValidateIdToken(openIdData.IdentityToken, true, out token);
                //set principal
                httpContext.User = claimPrincipal;
                System.Threading.Thread.CurrentPrincipal = claimPrincipal;
                var isAuth = claimPrincipal.Identity.IsAuthenticated;
                //cache Authorization Data
                httpContext.Items.Add(Const.AuthorizationDataKey, openIdData);
            }
            catch(Exception)
            {
                // ignored
            }
        }

        private static void AuthenticateWithHeader(HttpContext httpContext, string authHeader)
        {
            var tokenString = authHeader.Substring("Bearer ".Length);
            try
            {
                SecurityToken token;
                var claimPrincipal = _tokenValidationService.ValidateAccessToken(tokenString, out token);
                //set principal
                httpContext.User = claimPrincipal;
                System.Threading.Thread.CurrentPrincipal = claimPrincipal;
                var isAuth = claimPrincipal.Identity.IsAuthenticated;
            }
            catch(Exception)
            {
                throw;
            }
        }

        /// <summary>
        /// Starts the authentication flow on access denied.
        /// NOTE: typically, call to this method should be placed into  'Application_EndRequest' HttpApplication event handler.
        /// NOTE: XMLHttpRequest (ajax or webapi) requests get ignored by default!
        /// </summary>
        public static void StartAuthenticationOnAccessDenied()
        {
            var httpContext = HttpContext.Current;
            if(httpContext.Response.StatusCode == (int)HttpStatusCode.Unauthorized)
            {
                var request = httpContext.Request;
                if(request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return;
                }
                StartAuthenticationFlow();
            }
        }

        /// <summary>
        /// Starts the logout flow.
        /// </summary>
        /// <param name="landingPageUrl">The landing page URL.</param>
        public static void StartLogoutFlow(string landingPageUrl)
        {
            StartLogoutFlowAsync(landingPageUrl).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Starts the logout flow asynchronous.
        /// </summary>
        /// <param name="landingPageUrl">The landing page URL.</param>
        /// <returns></returns>
        public static async Task StartLogoutFlowAsync(string landingPageUrl)
        {
            var httpContext = HttpContext.Current;
            ExpireAuthorizationCookie(httpContext);
            if(!httpContext.User.Identity.IsAuthenticated)
            {
                httpContext.Response.Redirect(landingPageUrl);
                return;
            }
            var opts = Options;
            var tuple = await _idsService.GetDiscoveryResponseAsync(Options.Authority).ConfigureAwait(false);
            var disco = tuple.Item1;
            if(disco == null)
            {
                RedirectToError(httpContext, tuple.Item2, tuple.Item3);
                return;
            }
            //create state cookie
            var stateCookie = new HttpCookie(Const.StateCookieName);
            stateCookie.Value = landingPageUrl ?? "~/";
            stateCookie.Expires = DateTime.Now.AddMinutes(20);
            stateCookie.HttpOnly = true;
            //set cookies
            httpContext.Response.Cookies.Add(stateCookie);
            //create redirect url
            var openIdAuthData = httpContext.Items[Const.AuthorizationDataKey] as AuthorizationData;
            var idToken = "";
            if(openIdAuthData != null)
            {
                idToken = openIdAuthData.IdentityToken;
            }
            var uri = httpContext.Request.Url;
            var url = new EndSessionRequest(disco.EndSessionEndpoint).CreateEndSessionUrl(
                idToken: idToken,
                redirectUri: httpContext.BaseUrl() + opts.Authentication.SignOutCallbackEndpoint,
                state: stateCookie.Value
            );
            httpContext.Response.Redirect(url);
        }

        internal static void SignOutCallback(HttpContext httpContext)
        {
            var stateCookie = httpContext.Request.Cookies[Const.StateCookieName];
            var url = "~/";
            if(stateCookie != null)
            {
                url = stateCookie.Value;
            }
            httpContext.Response.Redirect(url);
        }

        private static void ExpireAuthorizationCookie(HttpContext httpContext)
        {
            var d = DateTime.Now.AddDays(-1);
            var cookie = new HttpCookie(Const.AuthorizationCookieName)
            {
                Value = "",
                Expires = d,
            };
            httpContext.Response.Cookies.Set(cookie);
            var i = 1;
            while(httpContext.Request.Cookies[Const.AuthorizationCookieName + "." + i] != null)
            {
                cookie = new HttpCookie(Const.AuthorizationCookieName + "." + i) {
                    Value = "",
                    Expires = d,
                };
                httpContext.Response.Cookies.Set(cookie);
                i++;
            }
        }

        public static string GetUserAccessToken()
        {
            return GetUserAccessTokenAsync().GetAwaiter().GetResult();
        }

        public static async Task<string> GetUserAccessTokenAsync()
        {
            var httpContext = HttpContext.Current;
            var openIdData = httpContext.Items[Const.AuthorizationDataKey] as AuthorizationData;
            if(openIdData == null)
            {
                return null;
            }
            if(openIdData.AccessToken != null)
            {
                return openIdData.AccessToken;
            }
            //request from ids
            var result = await _idsService.GetUserAccessTokenAsync().ConfigureAwait(false);
            //when successful service will update token cache 'OpenIdAuthorizationData'
            //we need to update OpenId cookie with new information
            SetAuthCookie(httpContext, openIdData);

            return result;
        }

        /// <summary>
        /// Gets the service instance. Can be used to extract the Open Id related service instance to register it with IOC container.
        /// NOTE: Only IOpenIdService is supported at this time.
        /// </summary>
        /// <typeparam name="T">Service Interface</typeparam>
        /// <returns>
        /// Instance of the requested service.
        /// </returns>
        /// <exception cref="System.ArgumentException"></exception>
        public static T GetServiceInstance<T>()
        {
            if(typeof(T) != typeof(IOpenIdService))
            {
                throw new ArgumentException($"Unsupported service types '{typeof(T).FullName}'.");
            }
            return (T)(IOpenIdService)_idsService;
        }
    }
}
