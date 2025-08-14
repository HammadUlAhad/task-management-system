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
        
        [Required(ErrorMessage = "Description is required")]
        [StringLength(1000, ErrorMessage = "Description cannot exceed 1000 characters")]
        public string Description { get; set; } = string.Empty;
        
        [Required(ErrorMessage = "Priority is required")]
        [EnumDataType(typeof(TaskPriority), ErrorMessage = "Invalid priority value")]
        public TaskPriority Priority { get; set; }
        
        [DataType(DataType.DateTime)]
        public DateTime? DueDate { get; set; }
        
        [EnumDataType(typeof(TaskStatus), ErrorMessage = "Invalid status value")]
        public TaskStatus Status { get; set; } = TaskStatus.Pending;
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
        public string Description { get; set; } = string.Empty;
        public TaskPriority Priority { get; set; }
        public DateTime? DueDate { get; set; }
        public TaskStatus Status { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
    }
}
