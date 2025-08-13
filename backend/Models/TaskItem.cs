using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace backend.Models
{
    [Table("Tasks")]
    public class TaskItem : BaseEntity
    {
        [Required(ErrorMessage = "Title is required")]
        [StringLength(200, MinimumLength = 1, ErrorMessage = "Title must be between 1 and 200 characters")]
        [Column(TypeName = "nvarchar(200)")]
        public string Title { get; set; } = string.Empty;
        
        [StringLength(1000, ErrorMessage = "Description cannot exceed 1000 characters")]
        [Column(TypeName = "nvarchar(1000)")]
        public string? Description { get; set; }
        
        [Required(ErrorMessage = "Priority is required")]
        [Column(TypeName = "int")]
        public TaskPriority Priority { get; set; }
        
        [Required(ErrorMessage = "Due date is required")]
        [Column(TypeName = "datetime2")]
        public DateTime DueDate { get; set; }
        
        [Required(ErrorMessage = "Status is required")]
        [Column(TypeName = "int")]
        public TaskStatus Status { get; set; } = TaskStatus.Pending;
        
        // Business logic methods (not mapped to database)
        public bool IsOverdue() => DateTime.UtcNow > DueDate && Status != TaskStatus.Completed;
        public bool IsHighPriority() => Priority == TaskPriority.High;
    }
    
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum TaskPriority
    {
        Low = 0,
        Medium = 1,
        High = 2
    }
    
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum TaskStatus
    {
        Pending = 0,
        InProgress = 1,
        Completed = 2,
        Archived = 3
    }
}
