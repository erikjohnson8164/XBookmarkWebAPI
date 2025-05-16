using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using Newtonsoft.Json;

var builder = WebApplication.CreateBuilder(args);

// Add logging for detailed error diagnostics
builder.Services.AddLogging(logging =>
{
    logging.AddConsole();
    logging.AddDebug();
    logging.SetMinimumLevel(LogLevel.Information);
});

// Add services to the container
builder.Services.AddControllers();


// Add authorization services for UseAuthorization middleware
builder.Services.AddAuthorization();

// Configure session management for OAuth state and code verifier
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(10);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

// Add HttpClient for OAuth token requests
builder.Services.AddHttpClient();

// Add Swagger for API documentation
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "X Bookmark Sender API", Version = "v1" });
});

// Configure Kestrel to use HTTPS on localhost:7235
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenLocalhost(7235, listenOptions =>
    {
        listenOptions.UseHttps();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage(); // Detailed error pages for development
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "X Bookmark Sender API v1");
        c.RoutePrefix = "swagger";
    });
}

// Global exception handling middleware
app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
        var exception = context.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>()?.Error;
        logger.LogError(exception, "Unexpected error occurred");

        context.Response.StatusCode = 500;
        await context.Response.WriteAsync($"Unexpected error: {exception?.Message ?? "Unknown error"}");
    });
});

app.UseHttpsRedirection();
app.UseRouting();
app.UseSession();
app.UseAuthorization();
app.MapControllers();

app.Run();