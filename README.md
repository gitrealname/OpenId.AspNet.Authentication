# OpenId.AspNet.Authentication

OpenId connect authentication for legacy ASP.NET web applications

## Configuration

```csharp
//file: Global.asax.cs
protected void Application_Start()
{
    OpenIdAuthentication.Configure(new OpenIdConnectOptions()
    {
        Authority = "http://localhost:5000",
        ClientId = "mvc",
        ClientSecret = "secret",
        Authentication = 
        {
            ErrorUrl = "~/Home/Error",
            ResourceList = new List<string>( ), // {"offline_access api1"},
        },
        RequireHttps = false,
        //prevent CSRF attacks on ajax/api endpoints 
        //by demanding 'Authorization: Bearer ... ' header instead of cookie
        DemandAuthorizationHeaderForEndpointPrefixes = new List<string>() 
        {
            "~/Ajax/GetDataSecured",
            "~/api", 
        }
    });
    ...
    AreaRegistration.RegisterAllAreas();
    ...
```

### [IdentityServer4](https://github.com/IdentityServer/IdentityServer4) Client Configuration example

```csharp
...
// OpenID Connect hybrid flow and client credentials client (MVC)
new Client
{
    ClientId = "mvc",
    ClientName = "MVC Client",
    
    AllowedGrantTypes = GrantTypes.HybridAndClientCredentials,

    ClientSecrets = 
    {
        new Secret("secret".Sha256())
    },

    RedirectUris = { "http://localhost:5002/signin-oidc" },
    PostLogoutRedirectUris = { "http://localhost:5002/signout-callback-oidc" },

    AllowedScopes = 
    {
        IdentityServerConstants.StandardScopes.OpenId,
        IdentityServerConstants.StandardScopes.Profile,
        "api1"
    },
    AllowOfflineAccess = true
}
...
```

## Typical wiring

```csharp
//file: Global.asax.cs
...
protected void Application_AuthenticateRequest(object sender, EventArgs e)
{
    OpenIdAuthentication.Authenticate();
}

protected void Application_EndRequest(object sender, EventArgs e)
{
    OpenIdAuthentication.StartAuthenticationOnAccessDenied();
}
...
```

## Registering Service with IOC container
```csharp
...
var instance = OpenIdAuthentication.GetServiceInstance<IOpenIdService>();
builder.RegisterInstance<IOpenIdService>(instance);
...
```

## Passing Access Token to SPA

```csharp
...
[Authorize]
public ActionResult OpenSPA()
{
    ViewBag.TitleSuffix = "Single page app.";
    ViewBag.AccessToken = OpenIdAuthentication.GetUserAccessToken(); 
    return View("");
}
...
```

```html
<script>
...
    var accessToken = "@ViewBag.AccessToken";
    ...
    $.ajax({
        headers: { Authorization:  "Bearer " + accessToken },
        contentType: "application/json",
        dataType: "json",
        url: "Ajax/GetDataSecured",
        method: "GET",
        success: function (response) { ... },
        error: function (err) { ... }
    });
    ...
</script>
```

## Api

### OpenIdAuthentication methods

```csharp
/// <summary>
/// Configures the Authentication layer.
/// </summary>
/// <param name="options">The options.</param>
public static void Configure(OpenIdConnectOptions options) {...}

/// <summary>
/// Starts the authentication flow.
/// </summary>
/// <param name="landingPageUrl">The landing page URL.</param>
public static void StartAuthenticationFlow(string landingPageUrl = null) {...}

/// <summary>
/// Starts the authentication flow asynchronous.
/// </summary>
/// <param name="landingPageUrl">The landing page URL.</param>
/// <returns></returns>
public static async Task StartAuthenticationFlowAsync(string landingPageUrl = null) {...}

/// <summary>
/// Authenticates request.
/// In case if both cookie and Authorization: Bearer header are present, 
/// Authorization will be performed using the Header!
/// NOTE: typically, call to this method should be placed into 'Application_AuthenticateRequest'
/// HttpApplication event handler.
/// </summary>
public static void Authenticate() {...}

/// <summary>
/// Starts the authentication flow on access denied.
/// NOTE: typically, call to this method should be placed into  'Application_EndRequest' 
/// HttpApplication event handler.
/// NOTE: XMLHttpRequest (ajax or web-api) requests get ignored by default!
/// </summary>
public static void StartAuthenticationOnAccessDenied() {...}

/// <summary>
/// Starts the logout flow.
/// </summary>
/// <param name="landingPageUrl">The landing page URL.</param>
public static void StartLogoutFlow(string landingPageUrl) {...}

/// <summary>
/// Starts the logout flow asynchronous.
/// </summary>
/// <param name="landingPageUrl">The landing page URL.</param>
/// <returns></returns>
public static async Task StartLogoutFlowAsync(string landingPageUrl) {...}

/// <summary>
/// Gets the service instance. Can be used to extract the Open Id related service instance to register it with IOC container.
/// NOTE: Only IOpenIdService is supported at this time.
/// </summary>
/// <typeparam name="T">Service Interface</typeparam>
/// <returns>
/// Instance of the requested service.
/// </returns>
/// <exception cref="System.ArgumentException"></exception>
public static T GetServiceInstance<T>() {...}

```

### [IOpenIdService](https://github.com/gitrealname/OpenId.AspNet.Authentication/blob/master/IOpenIdService.cs)
