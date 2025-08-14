using Microsoft.AspNetCore.Mvc;
using backend.Models;
using backend.Services;
using backend.DTOs;

namespace backend.Controllers
{
    [ApiController]
    [Route("api/tasks")]
    public class TasksController : ControllerBase
    {
        private readonly ITaskService _taskService;
        private readonly ILogger<TasksController> _logger;
        
        public TasksController(ITaskService taskService, ILogger<TasksController> logger)
        {
            _taskService = taskService;
            _logger = logger;
        }
        
        /// <summary>
        /// GET /api/tasks - Retrieve all tasks with optional filtering and pagination
        /// </summary>
        [HttpGet]
        public async Task<ActionResult<IEnumerable<TaskDto>>> GetAllTasks(
            [FromQuery] string? priority = null, 
            [FromQuery] string? status = null,
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 10)
        {
            var tasks = await _taskService.GetAllTasksAsync();
            
            // Apply filtering if parameters are provided
            if (!string.IsNullOrEmpty(priority) && Enum.TryParse<TaskPriority>(priority, true, out var priorityEnum))
            {
                tasks = tasks.Where(t => t.Priority == priorityEnum).ToList();
            }
            
            if (!string.IsNullOrEmpty(status) && Enum.TryParse<backend.Models.TaskStatus>(status, true, out var statusEnum))
            {
                tasks = tasks.Where(t => t.Status == statusEnum).ToList();
            }
            
            // Apply pagination
            var totalTasks = tasks.Count();
            var paginatedTasks = tasks
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToList();
            
            var taskDtos = paginatedTasks.Select(MapToDto);
            
            // Add pagination metadata to response headers
            Response.Headers["X-Total-Count"] = totalTasks.ToString();
            Response.Headers["X-Page"] = page.ToString();
            Response.Headers["X-Page-Size"] = pageSize.ToString();
            Response.Headers["X-Total-Pages"] = ((int)Math.Ceiling((double)totalTasks / pageSize)).ToString();
            
            return Ok(taskDtos);
        }
        
        /// <summary>
        /// GET /tasks/{id} - Retrieve a specific task
        /// </summary>
        [HttpGet("{id}")]
        public async Task<ActionResult<TaskDto>> GetTask(int id)
        {
            var task = await _taskService.GetTaskByIdAsync(id);
            if (task == null)
            {
                return NotFound($"Task with ID {id} not found.");
            }
            
            return Ok(MapToDto(task));
        }
        
        /// <summary>
        /// POST /tasks - Create a new task
        /// </summary>
        [HttpPost]
        public async Task<ActionResult<TaskDto>> CreateTask([FromBody] CreateTaskDto createTaskDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            
            var task = new TaskItem
            {
                Title = createTaskDto.Title,
                Description = createTaskDto.Description,
                Priority = createTaskDto.Priority,
                DueDate = createTaskDto.DueDate,
                Status = createTaskDto.Status,
            };
            
            var createdTask = await _taskService.CreateTaskAsync(task);
            var taskDto = MapToDto(createdTask);
            
            return CreatedAtAction(nameof(GetTask), new { id = createdTask.Id }, taskDto);
        }
        
        /// <summary>
        /// PUT /tasks/{id} - Update a specific task
        /// </summary>
        [HttpPut("{id}")]
        public async Task<ActionResult<TaskDto>> UpdateTask(int id, [FromBody] UpdateTaskDto updateTaskDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var existingTask = await _taskService.GetTaskByIdAsync(id);
            if (existingTask == null)
            {
                return NotFound($"Task with ID {id} not found.");
            }

            // Apply updates only if values are provided
            var updatedTask = new TaskItem
            {
                Id = id,
                Title = updateTaskDto.Title ?? existingTask.Title,
                Description = updateTaskDto.Description ?? existingTask.Description,
                Priority = updateTaskDto.Priority ?? existingTask.Priority,
                DueDate = updateTaskDto.DueDate ?? existingTask.DueDate,
                Status = updateTaskDto.Status ?? existingTask.Status,
                CreatedAt = existingTask.CreatedAt,
                UpdatedAt = existingTask.UpdatedAt
            };

            var result = await _taskService.UpdateTaskAsync(id, updatedTask);
            if (result == null)
            {
                return NotFound($"Task with ID {id} not found.");
            }

            return Ok(MapToDto(result));
        }
        
        /// <summary>
        /// DELETE /tasks/{id} - Delete a specific task
        /// </summary>
        [HttpDelete("{id}")]
        public async Task<ActionResult> DeleteTask(int id)
        {
            var success = await _taskService.DeleteTaskAsync(id);
            if (!success)
            {
                return NotFound($"Task with ID {id} not found.");
            }
            
            return NoContent();
        }
        
        private static TaskDto MapToDto(TaskItem task)
        {
            return new TaskDto
            {
                Id = task.Id,
                Title = task.Title,
                Description = task.Description,
                Priority = task.Priority,
                DueDate = task.DueDate,
                Status = task.Status,
                CreatedAt = task.CreatedAt,
                UpdatedAt = task.UpdatedAt
            };
        }
    }
}
