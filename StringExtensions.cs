using System;
using System.Collections.Generic;
using System.Text;

namespace OpenId.AspNet.Authentication
{
    internal static class StringExtensions
    {
        public static string RemoveTrailingSlash(this string url)
        {
            if(url != null && url.EndsWith("/"))
                url = url.Substring(0, url.Length - 1);
            return url;
        }

        public static string ToBase64(this string str)
        {
            var b = Encoding.UTF8.GetBytes(str);
            var result = Convert.ToBase64String(b);
            return result;
        }

        public static string FromBase64(this string str)
        {
            var b = Convert.FromBase64String(str);
            var result = Encoding.UTF8.GetString(b);
            return result;
        }

        public static IEnumerable<string> Split(this string str, int chunkSize)
        {
            for(var i = 0; i < str.Length; i += chunkSize)
            {
                yield return str.Substring(i, Math.Min(chunkSize, str.Length - i));
            }
        }
    }
}
