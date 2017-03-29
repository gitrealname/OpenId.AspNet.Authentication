using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;
using System.Web.Security;
using IdentityModel;
using IdentityModel.Client;

namespace OpenId.AspNet.Authentication
{
    internal class AuthorizationData
    {
        public Dictionary<string,string> Values { get; }

        public AuthorizationData(AuthorizeResponse response, JwtSecurityToken securityToken)
        {
            Values = response.Values;
            _securityToken = securityToken;
            Values.Remove(OidcConstants.AuthorizeResponse.Error);
            Values.Remove(OidcConstants.AuthorizeResponse.ErrorDescription);
        }

        private AuthorizationData(Dictionary<string,string> values)
        {
            Values = values;
        }

        public string Scope => TryGet(OidcConstants.AuthorizeResponse.Scope);
        public string Code
        {
            get { return TryGet(OidcConstants.AuthorizeResponse.Code); }
            set { Values[OidcConstants.AuthorizeResponse.Code] = value; }
        }
        public string AccessToken
        {
            get { return TryGet(OidcConstants.AuthorizeResponse.AccessToken); }
            internal set { Values[OidcConstants.AuthorizeResponse.AccessToken] = value; }
        }

        public DateTime AccessTokenExpirationTime
        {
            get
            {
                long filetime;
                long.TryParse(this.TryGet("AccessTokenExpirationTime"), out filetime);
                return DateTime.FromFileTime(filetime);
            }
            set
            {
                var str = value.ToFileTime().ToString();
                Values["AccessTokenExpirationTime"] = str;
            }
        }

        public string TokenType => TryGet(OidcConstants.AuthorizeResponse.TokenType);
        public string RefreshToken
        {
            get { return TryGet(OidcConstants.AuthorizeResponse.RefreshToken); }
            internal set { Values[OidcConstants.AuthorizeResponse.RefreshToken] = value; }
        }

        public string IdentityToken => TryGet(OidcConstants.AuthorizeResponse.IdentityToken);
        public long ExpiresIn
        {
            get
            {
                long result;
                long.TryParse(this.TryGet(OidcConstants.AuthorizeResponse.ExpiresIn), out result);
                return result;
            }
        }

        private JwtSecurityToken _securityToken;
        public JwtSecurityToken SecurityToken
        {
            get
            {
                if(_securityToken == null)
                {
                    var encodedToken = IdentityToken;
                    if(encodedToken != null)
                    {
                        var tokenHandler = new JwtSecurityTokenHandler();
                        _securityToken = tokenHandler.ReadJwtToken(encodedToken);
                    }
                }
                return _securityToken;
            }
        }

        public string TryGet(string type)
        {
            string encodedValue;
            if(this.Values.TryGetValue(type, out encodedValue))
            {
                return WebUtility.UrlDecode(encodedValue);

            }
            return (string)null;
        }

        /// <summary>
        /// Encrypts this instance for further storage in the cookie or session
        /// </summary>
        /// <returns></returns>
        public string Encrypt()
        {
            var bf = new BinaryFormatter();
            byte[] bytes;
            using(MemoryStream ms = new MemoryStream())
            {
                bf.Serialize(ms, Values);
                bytes =  ms.ToArray();
            }
            var encryptedBytes = MachineKey.Protect(bytes, Const.MachineKeyProtectPurpose);
            var result = Convert.ToBase64String(encryptedBytes);
            return result;
        }

        /// <summary>
        /// Creates instance from encrypted string.
        /// </summary>
        /// <param name="encryptedString">The encrypted string. <see cref="Encrypt"/></param>
        /// <returns></returns>
        public static AuthorizationData CreateFromEncryptedString(string encryptedString)
        {
            if(encryptedString == null)
            {
                return null;
            }
            var encryptedBytes = Convert.FromBase64String(encryptedString);
            var bytes = MachineKey.Unprotect(encryptedBytes, Const.MachineKeyProtectPurpose);
            Dictionary<string, string> values;
            using(MemoryStream ms = new MemoryStream(bytes))
            {
                var br = new BinaryFormatter();
                values = (Dictionary<string,string>)br.Deserialize(ms);
            }

            var result = new AuthorizationData(values);
            return result;
        }
    }
}
