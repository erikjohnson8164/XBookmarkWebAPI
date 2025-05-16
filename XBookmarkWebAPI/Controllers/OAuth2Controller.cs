using Microsoft.AspNetCore.Mvc;
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Web;

namespace OAuth2PKCE
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private static readonly string ClientId = "azNIWGxOcC1nTFlqWjU0U2k0Vkw6MTpjaQ"; // Replace with your Client ID
        private static readonly string RedirectUri = "https://localhost:7235/api/Auth/callback"; // Replace with your Redirect URI
        private static readonly string UserId = "YOUR_X_USER_ID"; // Replace with your X account user ID
        private static string CodeVerifier; // Store temporarily (in memory for simplicity)
        private static string ExpectedState; // Store temporarily for state verification

        // Endpoint to initiate the OAuth flow
        [HttpGet("start-auth")]
        public IActionResult StartAuth()
        {
            // Generate random state
            string state = GenerateRandomString(32);
            ExpectedState = state; // Store for callback verification

            // Generate PKCE code verifier and code challenge
            string codeVerifier = GenerateCodeVerifier();
            string codeChallenge = GenerateCodeChallenge(codeVerifier, "S256");
            CodeVerifier = codeVerifier; // Store for later use in token exchange

            // Define scopes (bookmark.read for accessing bookmarks)
            string[] scopes = { "bookmark.read" }; // Add more scopes if needed, e.g., "users.read"
            string scope = string.Join(" ", scopes);

            // Construct the authorize URL
            string authorizeUrl = ConstructAuthorizeUrl(ClientId, RedirectUri, scope, state, codeChallenge, "S256");

            // Return the authorize URL and code verifier
            return Ok(new { authUrl = authorizeUrl, codeVerifier });
        }

        // Callback endpoint for X redirect
        [HttpGet("callback")]
        public async Task<IActionResult> Callback([FromQuery] string code, [FromQuery] string state, [FromQuery] string error = null)
        {
            // Handle error if present
            if (!string.IsNullOrEmpty(error))
            {
                return BadRequest(new { error, message = "Authentication failed" });
            }

            // Verify state
            if (state != ExpectedState)
            {
                return BadRequest(new { error = "invalid_state", message = "State mismatch" });
            }

            // Exchange code for access token
            string accessToken;
            try
            {
                accessToken = await ExchangeCodeForTokenAsync(code, CodeVerifier, ClientId);
            }
            catch (HttpRequestException ex)
            {
                return BadRequest(new { error = "token_exchange_failed", message = ex.Message });
            }

            // Get bookmarks
            string bookmarks;
            try
            {
                bookmarks = await GetBookmarksAsync(accessToken, UserId);
            }
            catch (HttpRequestException ex)
            {
                return BadRequest(new { error = "bookmarks_failed", message = ex.Message });
            }

            // Return access token and bookmarks
            return Ok(new { accessToken, bookmarks });
        }

        // Generate a random string for state or code verifier
        private static string GenerateRandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
            byte[] randomBytes = new byte[length];
            using(var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            char[] result = new char[length];
            for (int i = 0; i < length; i++)
            {
                result[i] = chars[randomBytes[i] % chars.Length];
            }
            return new string(result);
        }

        // Generate PKCE code verifier (43-128 characters)
        private static string GenerateCodeVerifier()
        {
            return GenerateRandomString(64); // Recommended length
        }

        // Generate PKCE code challenge from code verifier
        private static string GenerateCodeChallenge(string codeVerifier, string method)
        {
            if (method == "S256")
            {
                using (var sha256 = SHA256.Create())
                {
                    byte[] hash = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
                    return Base64UrlEncode(hash);
                }
            }
            else // plain
            {
                return codeVerifier;
            }
        }

        // Base64 URL encode (for S256 code challenge)
        private static string Base64UrlEncode(byte[] input)
        {
            string base64 = Convert.ToBase64String(input);
            return base64.Replace("+", "-").Replace("/", "_").TrimEnd('=');
        }

        // Construct the OAuth 2.0 authorize URL
        private static string ConstructAuthorizeUrl(string clientId, string redirectUri, string scope, string state, string codeChallenge, string codeChallengeMethod)
        {
            var queryParams = new[]
            {
                ("response_type", "code"),
                ("client_id", clientId),
                ("redirect_uri", redirectUri),
                ("scope", scope),
                ("state", state),
                ("code_challenge", codeChallenge),
                ("code_challenge_method", codeChallengeMethod)
            };

            var queryString = string.Join("&", queryParams.Select(p => $"{p.Item1}={HttpUtility.UrlEncode(p.Item2)}"));
            return $"https://x.com/i/oauth2/authorize?{queryString}";
        }

        // Exchange authorization code for access token
        private async Task<string> ExchangeCodeForTokenAsync(string code, string codeVerifier, string clientId)
        {
            using var httpClient = new HttpClient();
            var tokenUrl = "https://api.x.com/2/oauth2/token";

            var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "client_id", clientId },
                { "grant_type", "authorization_code" },
                { "code", code },
                { "redirect_uri", RedirectUri },
                { "code_verifier", codeVerifier }
            });

            var response = await httpClient.PostAsync(tokenUrl, content);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadFromJsonAsync<JsonElement>();
            return json.GetProperty("access_token").GetString();
        }

        // Retrieve bookmarks using the access token
        private async Task<string> GetBookmarksAsync(string accessToken, string userId)
        {
            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var bookmarksUrl = $"https://api.x.com/2/users/{userId}/bookmarks";
            var response = await httpClient.GetAsync(bookmarksUrl);
            response.EnsureSuccessStatusCode();

            return await response.Content.ReadAsStringAsync();
        }
    }
}