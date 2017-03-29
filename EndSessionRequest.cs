using System;
using System.Collections.Generic;
using IdentityModel.Client;

namespace OpenId.AspNet.Authentication
{
    public class EndSessionRequest : AuthorizeRequest
    {

        public EndSessionRequest(Uri endSessionEndpoint) : base(endSessionEndpoint) {}

        public EndSessionRequest(string endSessionEndpoint) : base(endSessionEndpoint) { }

        public string CreateEndSessionUrl(string idToken, string redirectUri, string state = null)
        {
            var values = new Dictionary<string, string>();

            if(!string.IsNullOrWhiteSpace(idToken))
                values.Add("id_token_hint", idToken);
            if(!string.IsNullOrWhiteSpace(redirectUri))
                values.Add("post_logout_redirect_uri", redirectUri);
            if(!string.IsNullOrWhiteSpace(state))
                values.Add("state", state);

            var result = this.Create(values);
            return result;
        }
    }
}
