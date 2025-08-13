using backend.Models;

namespace backend.Services
{
    public interface ITaskEventPublisher
    {
        Task PublishHighPriorityTaskEventAsync(TaskItem task, string action);
    }
    
    public class TaskEventPublisher : ITaskEventPublisher
    {
        private readonly ILogger<TaskEventPublisher> _logger;
        private readonly string _criticalLogFilePath;
        
        public TaskEventPublisher(ILogger<TaskEventPublisher> logger, IConfiguration configuration)
        {
            _logger = logger;
            _criticalLogFilePath = configuration.GetValue<string>("Logging:CriticalTasksLogPath") ?? "logs/critical-tasks.log";
            
            // Ensure the directory exists
            var directory = Path.GetDirectoryName(_criticalLogFilePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }
        }
        
        public async Task PublishHighPriorityTaskEventAsync(TaskItem task, string action)
        {
            var logMessage = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}] CRITICAL: High priority task {action.ToLower()} - ID: {task.Id}, Title: '{task.Title}', Priority: {task.Priority}, Status: {task.Status}, Due: {task.DueDate:yyyy-MM-dd HH:mm:ss}";
            
            _logger.LogWarning("High priority task event: {Action} for task ID {TaskId}", action, task.Id);
            
            try
            {
                await File.AppendAllTextAsync(_criticalLogFilePath, logMessage + Environment.NewLine);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to write to critical tasks log file");
            }
        }
    }
}
