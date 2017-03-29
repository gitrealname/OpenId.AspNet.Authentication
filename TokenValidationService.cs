using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using IdentityModel;
using Microsoft.IdentityModel.Tokens;

namespace OpenId.AspNet.Authentication
{
    internal class TokenValidationService
    {
        private readonly OpenIdService _idsService;

        public TokenValidationService(OpenIdService idsService)
        {
            _idsService = idsService;
        }
        public ClaimsPrincipal ValidateIdToken(string encodedToken, bool relaxedValidation, out SecurityToken securityToken)
        {
            var principal = TokenValidationCommon(encodedToken, (vp, opts) => {
                vp.ValidateIssuerSigningKey = !relaxedValidation;
            }, out securityToken);

            return principal;
        }

        public ClaimsPrincipal ValidateAccessToken(string encodedToken, out SecurityToken securityToken)
        {
            OpenIdConnectOptions options = null;
            var principal = TokenValidationCommon(encodedToken, (vp, opts) => {
                options = opts;
                vp.ValidateAudience = false; //in case of access token audience is 'anything' use scope validation instead
            }, out securityToken);

            //self request
            var clientIdClaim = principal.Claims.FirstOrDefault(c => c.Type == OidcConstants.TokenRequest.ClientId);
            if(clientIdClaim != null && clientIdClaim.Value == options.ClientId)
            {
                return principal;
            }
            //validate scope
            var scopeClaim = principal.Claims.FirstOrDefault(c => c.Type == OidcConstants.TokenRequest.Scope);
            var scopes = scopeClaim.Value.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if(scopes.All(v => v != options.ClientId))
            {
                throw new InvalidOperationException($"IDX99999: Scope claim doesn't contain '{options.ClientId}'. Access denied.");
            }

            return principal;
        }

        private ClaimsPrincipal TokenValidationCommon(string encodedToken, Action<TokenValidationParameters, OpenIdConnectOptions> adjustValidationParameters, out SecurityToken securityToken)
        {
            var opts = _idsService.Options;
            var tuple = _idsService.GetDiscoveryResponseAsync(opts.Authority).GetAwaiter().GetResult();
            var disco = tuple.Item1;
            if(disco == null)
            {
                throw new Exception(tuple.Item3);
            }

            ///see: https://github.com/IdentityServer/IdentityServer4.Samples/blob/dev/Clients/src/MvcManual/Controllers/HomeController.cs#L81
            var keys = new List<SecurityKey>();
            foreach(var webKey in disco.KeySet.Keys)
            {
                var e = Base64Url.Decode(webKey.E);
                var n = Base64Url.Decode(webKey.N);

                var key = new RsaSecurityKey(new RSAParameters { Exponent = e, Modulus = n }) { KeyId = webKey.Kid };

                keys.Add(key);
            }

            var tokenValidationParams = new TokenValidationParameters() {
                ValidAudiences = new string[]
                {
                    opts.ClientId,
                },
                ValidIssuers = opts.TrustedAuthoritiesSet.ToArray(),
                IssuerSigningKeys = keys,
                ValidateIssuerSigningKey = true,

                // Token will only be valid if not expired yet, with 5 minutes clock skew.
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ClockSkew = new TimeSpan(0, 5, 0),
            };


            //call adjuster
            adjustValidationParameters(tokenValidationParams, opts);

            var tokenHandler = new JwtSecurityTokenHandler();
            tokenHandler.InboundClaimTypeMap.Clear();
            var claimPrincipal = tokenHandler.ValidateToken(encodedToken, tokenValidationParams, out securityToken);
            return claimPrincipal;
        }

    }
}
