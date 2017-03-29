using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Web;
using IdentityModel.Client;

namespace OpenId.AspNet.Authentication
{
    internal class OpenIdService : IOpenIdService
    {
        internal readonly OpenIdConnectOptions Options;
        private readonly ConcurrentDictionary<string, DiscoveryResponse> _discoveryResposeMap = new ConcurrentDictionary<string, DiscoveryResponse>();


        internal OpenIdService(OpenIdConnectOptions options)
        {
            this.Options = options;
        }

        private DiscoveryClient CreateDiscoveryClient(string authorityUrl)
        {
            var policy = new DiscoveryPolicy {
                RequireKeySet = true,
                RequireHttps = Options.RequireHttps,
                ValidateIssuerName = true,
                ValidateEndpoints = true,
            };
            var client = new DiscoveryClient(authorityUrl);
            client.Policy = policy;
            return client;
        }

        internal async Task<Tuple<DiscoveryResponse, int, string>> GetDiscoveryResponseAsync(string authorityUrl)
        {
            authorityUrl = authorityUrl ?? Options.Authority;
            authorityUrl = authorityUrl.ToLowerInvariant().RemoveTrailingSlash();
            DiscoveryResponse result;
            if(_discoveryResposeMap.TryGetValue(authorityUrl, out result))
            {
                return new Tuple<DiscoveryResponse, int, string>(result, 0, null);
            }
            result = null;
            var client = CreateDiscoveryClient(authorityUrl);
            var idsInfo = await client.GetAsync().ConfigureAwait(false);
            if(idsInfo.ErrorType == ResponseErrorType.None)
            {
                _discoveryResposeMap[authorityUrl] = idsInfo;
                result = idsInfo;
            }
            return new Tuple<DiscoveryResponse, int, string>(result, (int)idsInfo.ErrorType, idsInfo.Error);
        }

        /// <summary>
        /// Gets the discovery information for specified Identity Server (Authority).
        /// </summary>
        /// <param name="authorityUrl">Optional. The authority URL.
        /// If not specified, then default Authority will be used <see cref="OpenIdConnectOptions"/>
        /// </param>
        /// <returns>
        /// Discover Response
        /// </returns>
        /// <exception cref="System.InvalidOperationException"></exception>
        public DiscoveryResponse GetDiscoveryInfo(string authorityUrl = null)
        {
            var result = GetDiscoveryInfoAsyc(authorityUrl).GetAwaiter().GetResult();
            return result;
        }

        /// <summary>
        /// Gets the discovery information for specified Identity Server (Authority).
        /// </summary>
        /// <param name="authorityUrl">Optional. The authority URL.
        /// If not specified, then default Authority will be used <see cref="OpenIdConnectOptions"/>
        /// </param>
        /// <returns>
        /// Discover Response
        /// </returns>
        /// <exception cref="System.InvalidOperationException"></exception>
        public async Task<DiscoveryResponse> GetDiscoveryInfoAsyc(string authorityUrl = null)
        {
            authorityUrl = authorityUrl ?? Options.Authority;
            var tuple = await GetDiscoveryResponseAsync(authorityUrl).ConfigureAwait(false);
            if(tuple.Item1 == null)
            {
                throw new InvalidOperationException($"Identity Server '{authorityUrl}' Discovery endpoint communication has failed.");
            }
            return tuple.Item1;
        }
        
        /// <summary>
        /// Gets the access token on behalf of currently logged user. 
        /// </summary>
        /// <returns></returns>
        public string GetUserAccessToken()
        {
            return GetUserAccessTokenAsync().GetAwaiter().GetResult();
        }

        /// <summary>
        /// Gets the access token on behalf of currently logged user. 
        /// </summary>
        /// <returns></returns>
        public async Task<string> GetUserAccessTokenAsync()
        {
            //get OpenId Authorization Data from the http context
            var httpContext = HttpContext.Current;
            var opts = Options;
            var openIdData = httpContext.Items[Const.AuthorizationDataKey] as AuthorizationData;
            if(openIdData == null)
            {
                return null;
            }

            if(openIdData.AccessToken != null)
            {
                return openIdData.AccessToken;
            }

            if(openIdData.Code == null)
            {
                return null;
            }

            //get discovery info
            var tuple = await GetDiscoveryResponseAsync(opts.Authority).ConfigureAwait(false);
            var disco = tuple.Item1;
            if(disco == null)
            {
                return null;
            }

            TokenResponse tokenResponse;
            var expirationTime = DateTime.Now;
            using(var tokenHttpClient = new TokenClient(
                address: disco.TokenEndpoint,
                clientId: opts.ClientId,
                clientSecret: opts.ClientSecret,
                style: AuthenticationStyle.PostValues
                ))
            {
                var uri = httpContext.Request.Url;
                var redirectUri = httpContext.BaseUrl() + opts.Authentication.SignInEndpoint;
                tokenResponse = await tokenHttpClient.RequestAuthorizationCodeAsync(openIdData.Code, redirectUri).ConfigureAwait(false);
            }

            if(tokenResponse.IsError)
            {
                throw new Exception(tokenResponse.Error);
            }

            openIdData.AccessToken = tokenResponse.AccessToken;
            openIdData.RefreshToken = tokenResponse.RefreshToken;
            openIdData.AccessTokenExpirationTime = expirationTime.AddSeconds(tokenResponse.ExpiresIn);
            //erase code, it cannot be reused anyway
            openIdData.Code = null;


            return tokenResponse.AccessToken;
        }

        /// <summary>
        /// Gets the Client/Application security token. That can be used to access OAuth2 resources
        /// </summary>
        /// <param name="resourceId">The resource identifier for which credentials are being requested</param>
        /// <param name="clientId">The Client identifier. Default: <see cref="OpenIdConnectOptions.ClientId" /></param>
        /// <param name="clientSecret">The client secret. Default: <see cref="OpenIdConnectOptions.ClientSecret" /></param>
        /// <param name="authorityUrl">The authority URL. <see cref="OpenIdConnectOptions.Authority" /></param>
        /// <returns>
        /// Encoded JWT token
        /// </returns>
        public string GetClientCredentials(string resourceId, string clientId = null, string clientSecret = null, string authorityUrl = null)
        {
            return GetClientCredentialsAsync(resourceId, clientId, clientSecret, authorityUrl).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Gets the client credentials asynchronous.
        /// </summary>
        /// <param name="resourceId">The resource identifier.</param>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="clientSecret">The client secret.</param>
        /// <param name="authorityUrl">The authority URL.</param>
        /// <returns></returns>
        /// <exception cref="System.ArgumentNullException">resourceId</exception>
        /// <exception cref="System.InvalidOperationException"></exception>
        public async Task<string> GetClientCredentialsAsync(string resourceId, string clientId = null, string clientSecret = null, string authorityUrl = null)
        {
            if(string.IsNullOrWhiteSpace(resourceId))
            {
                throw new ArgumentNullException(nameof(resourceId));
            }
            clientId = clientId ?? Options.ClientId;
            clientSecret = clientSecret ?? Options.ClientSecret;
            authorityUrl = authorityUrl ?? Options.Authority;

            //get Discover info
            var disco = await GetDiscoveryInfoAsyc(authorityUrl).ConfigureAwait(false);

            var tokenClient = new TokenClient(disco.TokenEndpoint, clientId, clientSecret);
            var tokenResponse = await tokenClient.RequestClientCredentialsAsync(resourceId).ConfigureAwait(false);

            if(tokenResponse.IsError)
            {
                throw new InvalidOperationException(tokenResponse.Error);
            }

            return tokenResponse.AccessToken;
        }
    }
}
