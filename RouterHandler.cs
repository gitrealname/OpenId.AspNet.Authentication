using System.Web;
using System.Web.Routing;

namespace OpenId.AspNet.Authentication
{
    public class RouterHandler : IRouteHandler
    {
        public RouterHandler()
        {

        }
        public IHttpHandler GetHttpHandler(RequestContext requestContext)
        {
            return new OpenIdMvcHttpHandler();
        }
    }

    public class OpenIdMvcHttpHandler : IHttpHandler
    {
        public OpenIdMvcHttpHandler()
        {
        }

        public void ProcessRequest(HttpContext context)
        {

            var oper = context.Request.Url.Segments[context.Request.Url.Segments.Length - 1];
            if(oper == OpenIdAuthentication.Options.Authentication.SignInEndpoint)
            {
                OpenIdAuthentication.SignInCallback(context);
            }
            else if(oper == OpenIdAuthentication.Options.Authentication.SignOutCallbackEndpoint)
            {
                OpenIdAuthentication.SignOutCallback(context);
            }
            else
            {
                OpenIdAuthentication.RedirectToError(context, 1000, $"Invalid OperId endpoint: {oper}.");
            }
        }

        public bool IsReusable => false;
    }
}
