
// ==============================================================================
// .NET / C# Client for FFRR REST API (`ffrr serve --bind 127.0.0.1:8090`)
// ==============================================================================
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

public class FfrrClient {
    private readonly HttpClient _http = new HttpClient();
    private readonly string _baseUrl;
    public FfrrClient(string baseUrl = "http://127.0.0.1:8090") => _baseUrl = baseUrl;

    public async Task<string> SearchAndReplaceAsync(string source, string find, string? replace = null, bool dryRun = true) {
        var payload = JsonSerializer.Serialize(new { source, find, replace, dry_run = dryRun });
        var res = await _http.PostAsync($"{_baseUrl}/v1/search", new StringContent(payload, Encoding.UTF8, "application/json"));
        return await res.Content.ReadAsStringAsync();
    }
}
