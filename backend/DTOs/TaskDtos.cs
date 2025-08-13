using System.ComponentModel.DataAnnotations;
using backend.Models;
using TaskStatus = backend.Models.TaskStatus;

namespace backend.DTOs
{
    public class CreateTaskDto
    {
        [Required(ErrorMessage = "Title is required")]
        [StringLength(200, MinimumLength = 1, ErrorMessage = "Title must be between 1 and 200 characters")]
        public string Title { get; set; } = string.Empty;
        
        [StringLength(1000, ErrorMessage = "Description cannot exceed 1000 characters")]
        public string? Description { get; set; }
        
        [Required(ErrorMessage = "Priority is required")]
        [EnumDataType(typeof(TaskPriority), ErrorMessage = "Invalid priority value")]
        public TaskPriority Priority { get; set; }
        
        [Required(ErrorMessage = "Due date is required")]
        [DataType(DataType.DateTime)]
        [FutureDate(ErrorMessage = "Due date must be in the future")]
        public DateTime DueDate { get; set; }
        
        [EnumDataType(typeof(TaskStatus), ErrorMessage = "Invalid status value")]
        public TaskStatus Status { get; set; } = TaskStatus.Pending;
        
        // CreatedAt and UpdatedAt are set by backend, not client
    }
    
    public class UpdateTaskDto
    {
        [StringLength(200, MinimumLength = 1, ErrorMessage = "Title must be between 1 and 200 characters")]
        public string? Title { get; set; }
        
        [StringLength(1000, ErrorMessage = "Description cannot exceed 1000 characters")]
        public string? Description { get; set; }
        
        [EnumDataType(typeof(TaskPriority), ErrorMessage = "Invalid priority value")]
        public TaskPriority? Priority { get; set; }
        
        [DataType(DataType.DateTime)]
        public DateTime? DueDate { get; set; }
        
        [EnumDataType(typeof(TaskStatus), ErrorMessage = "Invalid status value")]
        public TaskStatus? Status { get; set; }
        
        // UpdatedAt is set by backend, not client
    }
    
    public class TaskDto
    {
    public int Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public string? Description { get; set; }
    public TaskPriority Priority { get; set; }
    public DateTime DueDate { get; set; }
    public TaskStatus Status { get; set; }

    // Computed properties for better API responses
    public bool IsHighPriority { get; set; }
    public bool IsOverdue { get; set; }
    public int DaysUntilDue { get; set; }

    // Timestamps at the end
    public DateTime CreatedAt { get; set; }
    public DateTime? UpdatedAt { get; set; }
    }
    
    // Custom validation attributes
    public class FutureDateAttribute : ValidationAttribute
    {
        public override bool IsValid(object? value)
        {
            if (value is DateTime dateTime)
            {
                return dateTime > DateTime.UtcNow;
            }
            return true; // Let other attributes handle null values
        }
    }
}
