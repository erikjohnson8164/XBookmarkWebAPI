using Microsoft.AspNetCore.Mvc;
using System;
using System.Net;
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
        private static readonly string ClientSecret = "CI_xvIXmUbaLUWXOjSHgZMsOKjGhlpBRf-11OU9g5CVrJilhuD";
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
            string[] scopes = { "tweet.read", "users.read", "bookmark.read" };
            string scope = string.Join(" ", scopes); // Results in "tweet.read users.read bookmark.read"
            Console.WriteLine($"Raw scope: {scope}"); // Debug: Should be "tweet.read users.read bookmark.read"

            string encodedScope = Uri.EscapeDataString(scope); // Encodes spaces to %20: "tweet.read%20users.read%20bookmark.read"
            Console.WriteLine($"Encoded scope: {encodedScope}"); // Debug: Should be "tweet.read%20users.read%20bookmark.read"

            // Construct the authorize URL
            string authorizeUrl = ConstructAuthorizeUrl(ClientId, RedirectUri, encodedScope, state, codeChallenge, "S256");
            Console.WriteLine($"Final URL: {authorizeUrl}");

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
            string userId;
            try
            {
                userId = await GetUserIdAsync(accessToken);
            }
            catch (HttpRequestException ex)
            {
                return BadRequest(new { error = "getIdFailed", message = ex.Message });
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

            // Add Basic Authentication header
            var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{clientId}:{ClientSecret}"));
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

            // Prepare request body (do not include client_secret here)
            var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "client_id", clientId },
                { "grant_type", "authorization_code" },
                { "code", code },
                { "redirect_uri", RedirectUri },
                { "code_verifier", codeVerifier }
            });

            // Log request details for debugging
            Console.WriteLine($"Token request - ClientId: {clientId}, Code: {code}, RedirectUri: {RedirectUri}, CodeVerifier: {codeVerifier}");

            var response = await httpClient.PostAsync(tokenUrl, content);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                throw new HttpRequestException(
                    $"Token exchange failed: {(int)response.StatusCode} ({response.ReasonPhrase}). Response: {errorContent}");
            }

            var json = await response.Content.ReadFromJsonAsync<JsonElement>();
            return json.GetProperty("access_token").GetString();
        }
        //private async Task<string> ExchangeCodeForTokenAsync(string code, string codeVerifier, string clientId)
        //{
        //    using var httpClient = new HttpClient();
        //    var tokenUrl = "https://api.x.com/2/oauth2/token";

        //    var content = new FormUrlEncodedContent(new Dictionary<string, string>
        //    {
        //        { "client_id", clientId },
        //        { "client_secret", ClientSecret },
        //        { "grant_type", "authorization_code" },
        //        { "code", code },
        //        { "redirect_uri", RedirectUri },
        //        { "code_verifier", codeVerifier }
        //    });

        //    var response = await httpClient.PostAsync(tokenUrl, content);
        //    if (!response.IsSuccessStatusCode)
        //    {
        //        var errorContent = await response.Content.ReadAsStringAsync();
        //        throw new HttpRequestException(
        //            $"Token exchange failed: {(int)response.StatusCode} ({response.ReasonPhrase}). Response: {errorContent}");
        //    }

        //    var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        //    return json.GetProperty("access_token").GetString();
        //}

        // Retrieve bookmarks using the access token
        private async Task<string> GetBookmarksAsync(string accessToken, string userId)
        {
            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var bookmarksUrl = $"https://api.x.com/2/users/1620545947641188352/bookmarks?max_results=100" +
                              "&expansions=author_id,attachments.media_keys" +
                              "&user.fields=id,username,name,profile_image_url" +
                              "&media.fields=url,preview_image_url" +
                              "&tweet.fields=author_id,attachments";
            
            var response = await httpClient.GetAsync(bookmarksUrl);
            response.EnsureSuccessStatusCode();

            return await response.Content.ReadAsStringAsync();
        }

        private async Task<string> GetUserIdAsync(string accessToken)
        {
            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            var response = await httpClient.GetAsync("https://api.x.com/2/users/me");
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                throw new HttpRequestException($"Failed to get user ID: {response.StatusCode}, {errorContent}");
            }
            var json = await response.Content.ReadAsStringAsync();
            var data = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, string>>>(json);
            var userId = data["data"]["id"];
            Console.WriteLine($"User ID: {userId} (permanent for account erikj3102)");
            return userId;
        }
    }
}