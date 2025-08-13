using System.Text;

namespace backend.Middleware
{
    public class RequestLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RequestLoggingMiddleware> _logger;
        private readonly string _logFilePath;
        
        public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger, IConfiguration configuration)
        {
            _next = next;
            _logger = logger;
            _logFilePath = configuration.GetValue<string>("Logging:RequestLogPath") ?? "logs/api-requests.log";
            
            // Ensure the directory exists
            var directory = Path.GetDirectoryName(_logFilePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }
        }
        
        public async Task InvokeAsync(HttpContext context)
        {
            var startTime = DateTime.UtcNow;
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            // Log the incoming request
            await LogRequestAsync(context, startTime);
            
            // Continue processing the request
            await _next(context);
            
            stopwatch.Stop();
            
            // Log the response
            await LogResponseAsync(context, startTime, stopwatch.ElapsedMilliseconds);
        }
        
        private async Task LogRequestAsync(HttpContext context, DateTime timestamp)
        {
            var request = context.Request;
            var logEntry = new StringBuilder();
            
            logEntry.AppendLine($"[{timestamp:yyyy-MM-dd HH:mm:ss UTC}] INCOMING REQUEST");
            logEntry.AppendLine($"Method: {request.Method}");
            logEntry.AppendLine($"Endpoint: {request.Path}{request.QueryString}");
            logEntry.AppendLine($"Remote IP: {context.Connection.RemoteIpAddress}");
            logEntry.AppendLine($"User-Agent: {request.Headers.UserAgent}");
            logEntry.AppendLine($"Content-Type: {request.ContentType}");
            logEntry.AppendLine("---");
            
            try
            {
                await File.AppendAllTextAsync(_logFilePath, logEntry.ToString());
                _logger.LogInformation("API Request: {Method} {Path}", request.Method, request.Path);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to write to request log file");
            }
        }
        
        private async Task LogResponseAsync(HttpContext context, DateTime requestTime, long elapsedMs)
        {
            var logEntry = new StringBuilder();
            
            logEntry.AppendLine($"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}] RESPONSE");
            logEntry.AppendLine($"Status: {context.Response.StatusCode}");
            logEntry.AppendLine($"Content-Type: {context.Response.ContentType}");
            logEntry.AppendLine($"Duration: {elapsedMs}ms");
            logEntry.AppendLine($"Content-Length: {context.Response.ContentLength}");
            logEntry.AppendLine("================================");
            logEntry.AppendLine();
            
            try
            {
                await File.AppendAllTextAsync(_logFilePath, logEntry.ToString());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to write response to log file");
            }
        }
    }
}
