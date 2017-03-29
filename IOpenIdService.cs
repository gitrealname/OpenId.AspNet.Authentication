using System.Threading.Tasks;
using IdentityModel.Client;

namespace OpenId.AspNet.Authentication
{
    /// <summary>
    /// Collection of service to work with OpenId Connect and OAuth2 protocols
    /// </summary>
    public interface IOpenIdService
    {
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
        DiscoveryResponse GetDiscoveryInfo(string authorityUrl = null);

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
        Task<DiscoveryResponse> GetDiscoveryInfoAsyc(string authorityUrl = null);


        /// <summary>
        /// Gets the access token on behalf of currently logged user. 
        /// </summary>
        /// <returns></returns>
        string GetUserAccessToken();

        /// <summary>
        /// Gets the access token on behalf of currently logged user. 
        /// </summary>
        /// <returns></returns>
        Task<string> GetUserAccessTokenAsync();

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
        string GetClientCredentials(string resourceId, string clientId = null, string clientSecret = null, string authorityUrl = null);

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
        Task<string> GetClientCredentialsAsync(string resourceId, string clientId = null, string clientSecret = null, string authorityUrl = null);
    }
}
