using System.Collections.Generic;

namespace OpenId.AspNet.Authentication
{
    public class OpenIdAuthenticationOptions
    {

        /// <summary>
        /// Indicates that the authentication session lifetime (e.g. cookies) should match that of the authentication token.
        /// If the token does not provide lifetime information then normal session lifetimes will be used.
        /// This is disabled by default.
        /// Default: true
        /// </summary>
        //Todo: public bool UseTokenLifetime { get; set; }

        /// <summary>
        /// Gets or sets the 'response_type'.
        /// Default: "code id_token"
        /// </summary>
        //Todo: public string ResponseType { get; set; }


        /// <summary>
        /// Gets or sets a value indicating whether to request refresh key from the identity server.
        /// NOTE: if set, 'offline_access' scope should be permitted for the client
        /// Default: false
        /// </summary>
        public bool RequestRefreshKey { get; set; }

        /// <summary>
        /// Gets or sets the list of desired resource ids the client wishes to have an access to. 
        /// NOTE: requested resource must be explicitly authorized to this client by Identity Server.
        /// Example resource id: "api1"; "api2.read"
        /// </summary>
        public IList<string> ResourceList { get; set; }

        /// <summary>
        /// Gets or sets the open id connect sign-in endpoint.
        /// Default: "sign-oidc"
        /// </summary>
        public string SignInEndpoint { get; set; }


        /// <summary>
        /// Gets or sets the open id connect sign-out callback endpoint.
        /// Default: "signout-callback-oidc"
        /// </summary>
        public string SignOutCallbackEndpoint { get; set; }


        /// <summary>
        /// Gets or sets the authentication error URL.
        /// Place where user will be redirected to in case of any problems with authentication and identity server communication.
        /// Example: "~/Error/Authentication
        /// Final Url Example: http...../Error/Authentication?errorCode=...?errorMessage=....
        /// </summary>
        public string ErrorUrl { get; set; }

        public OpenIdAuthenticationOptions()
        {
            //ResponseType = "code id_token"; //hybrid flow!
            //UseTokenLifetime = false;
            RequestRefreshKey = false;
            SignInEndpoint = "signin-oidc";
            SignOutCallbackEndpoint = "signout-callback-oidc";
            ErrorUrl = "/";
            ResourceList = new List<string>();
        }
    }

    public class OpenIdConnectOptions
    {
        
        public OpenIdAuthenticationOptions Authentication { get; }
        /// <summary>
        /// Gets or sets the Authority to use when making OpenIdConnect calls.
        /// </summary>
        public string Authority { get; set; }

        /// <summary>Gets or sets the 'client_id'.</summary>
        public string ClientId { get; set; }

        /// <summary>Gets or sets the 'client_secret'.</summary>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets the trusted Authorities/issuers urls.
        /// NOTE: <see ref="Authority">is trusted by default</see>
        /// </summary>
        public IList<string> TrustedAuthorities { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to enforce HTTPS protocol for Identity server communication.
        /// Default: true.
        /// </summary>
        public bool RequireHttps { get; set; }


        /// <summary>
        /// Gets or sets list of (Ajax/WebApi) endpoints'  virtual path prefixes that must be authenticated/authorized 
        /// using 'Authorization' request header instead of cookie.
        /// Unless endpoint is not protected (listed), it is vulnerable to CSRF attack. 
        /// </summary>
        /// <value>
        /// The demand authorization header for endpoints.
        /// </value>
        public IList<string> DemandAuthorizationHeaderForEndpointPrefixes { get; set; }


        /// <summary>
        /// INTERNAL USE ONLY!
        /// Gets the trusted authorities set.
        /// </summary>
        /// <value>
        /// The trusted authorities set.
        /// </value>
        internal HashSet<string> TrustedAuthoritiesSet { get; set; }

        public OpenIdConnectOptions()
        {
            RequireHttps = true;
            Authentication = new OpenIdAuthenticationOptions();
            TrustedAuthorities = new List<string>();
            DemandAuthorizationHeaderForEndpointPrefixes = new List<string>();
        }
        
    }
}
