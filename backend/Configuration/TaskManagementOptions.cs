namespace backend.Configuration
{
    public class TaskManagementOptions
    {
        public const string SectionName = "TaskManagement";
        
        public int MaxTasksPerUser { get; set; } = 1000;
        public int DefaultPageSize { get; set; } = 20;
        public int MaxPageSize { get; set; } = 100;
        public TimeSpan TaskOverdueThreshold { get; set; } = TimeSpan.FromDays(1);
        
        // Validation settings
        public ValidationSettings Validation { get; set; } = new();
        
        // Logging settings
        public LoggingSettings Logging { get; set; } = new();
    }
    
    public class ValidationSettings
    {
        public int MinTitleLength { get; set; } = 1;
        public int MaxTitleLength { get; set; } = 200;
        public int MaxDescriptionLength { get; set; } = 1000;
        public bool RequireFutureDueDate { get; set; } = true;
    }
    
    public class LoggingSettings
    {
        public string RequestLogPath { get; set; } = "logs/api-requests.log";
        public string CriticalTasksLogPath { get; set; } = "logs/critical-tasks.log";
        public bool EnableRequestLogging { get; set; } = true;
        public bool EnableHighPriorityLogging { get; set; } = true;
    }
}
