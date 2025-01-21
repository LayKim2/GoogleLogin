using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using System.Security.Claims;
using Test.Auth;
using Test.Components;
using System.Net.Http.Headers;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<AuthenticationStateProvider, ServerAuthenticationStateProvider>();
builder.Services.AddAuthentication(AppConstants.AuthScheme)
    .AddCookie(AppConstants.AuthScheme, cookieOptions =>
    {
        cookieOptions.Cookie.Name = AppConstants.AuthScheme;
    })
    .AddGoogle(GoogleDefaults.AuthenticationScheme, googleOptions =>
    {
        googleOptions.ClientId = "94605561544-md5tee3juotjinm66p7qtgo8ubqts5jj.apps.googleusercontent.com";
        googleOptions.ClientSecret = "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";
        googleOptions.AccessDeniedPath = "/access-denied";
        googleOptions.SignInScheme = AppConstants.AuthScheme;
        googleOptions.CallbackPath = new PathString("/signin-google");  // 리디렉션 경로
    });

//builder.Services.AddAuthentication(options =>
//{
//    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
//    options.DefaultChallengeScheme = "Kakao"; // "Kakao"를 기본 Challenge로 설정
//})
//.AddCookie(options =>
//{
//    options.Cookie.HttpOnly = true;
//    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // HTTPS 전용
//    options.Cookie.SameSite = SameSiteMode.Lax; // OAuth 요청에 적합한 설정
//})
//.AddOAuth("Kakao", options =>
//{
//    options.ClientId = "b4f436e21e363b5faef09df87c109967";
//    options.ClientSecret = "3T3tFIBHzC9MsvhbpKPXcCmuTkJum55m";
//    options.CallbackPath = new PathString("/signin-kakao");
//    options.AuthorizationEndpoint = "https://kauth.kakao.com/oauth/authorize";
//    options.TokenEndpoint = "https://kauth.kakao.com/oauth/token";
//    options.UserInformationEndpoint = "https://kapi.kakao.com/v2/user/me";

//    options.Scope.Add("profile");
//    options.SaveTokens = true;

//    options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
//    options.ClaimActions.MapJsonKey(ClaimTypes.Name, "properties.nickname");
//    options.ClaimActions.MapJsonKey("profile_image", "properties.profile_image");

//    options.Events = new OAuthEvents
//    {
//        OnCreatingTicket = async context =>
//        {
//            var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
//            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);

//            var response = await context.Backchannel.SendAsync(request);
//            response.EnsureSuccessStatusCode();

//            var user = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
//            context.RunClaimActions(user.RootElement);
//        }
//    };
//});


builder.Services.AddHttpContextAccessor();

var app = builder.Build();


app.Use(async (context, next) =>
{
    // /login 경로로 접근하면 OAuth 인증을 시작
    if (context.Request.Path.StartsWithSegments("/login"))
    {
        var authProperties = new AuthenticationProperties
        {
            RedirectUri = "/after-login"  // 인증 성공 후 리디렉션할 경로
        };

        // 인증 요청을 트리거합니다.
        await context.ChallengeAsync(GoogleDefaults.AuthenticationScheme, authProperties);

        return;  // 인증 요청을 시작한 후 더 이상 요청을 처리하지 않음
    }

    await next();  // 그 외의 경로는 계속해서 처리
});

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/login"))
    {
        var authProperties = new AuthenticationProperties
        {
            RedirectUri = "/after-login"  // 인증 후 리디렉션될 URL
        };

        // OAuth 인증 요청을 트리거합니다.
        await context.ChallengeAsync(GoogleDefaults.AuthenticationScheme, authProperties);
        return;  // 인증 요청을 시작한 후 더 이상 요청을 처리하지 않습니다.
    }

    await next();  // 나머지 요청은 계속 처리
});

app.UseAuthentication();
app.UseAuthorization();

app.UseHttpsRedirection();


app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
