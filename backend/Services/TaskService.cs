using backend.Models;
using backend.Repositories;

namespace backend.Services
{
    public interface ITaskService
    {
        Task<IEnumerable<TaskItem>> GetAllTasksAsync();
        Task<TaskItem?> GetTaskByIdAsync(int id);
        Task<TaskItem> CreateTaskAsync(TaskItem task);
        Task<TaskItem?> UpdateTaskAsync(int id, TaskItem updatedTask);
        Task<bool> DeleteTaskAsync(int id);
    }
    
    public class TaskService : ITaskService
    {
        private readonly ITaskRepository _taskRepository;
        private readonly ITaskEventPublisher _eventPublisher;
        
        public TaskService(ITaskRepository taskRepository, ITaskEventPublisher eventPublisher)
        {
            _taskRepository = taskRepository;
            _eventPublisher = eventPublisher;
        }
        
        public async Task<IEnumerable<TaskItem>> GetAllTasksAsync()
        {
            return await _taskRepository.GetAllAsync();
        }
        
        public async Task<TaskItem?> GetTaskByIdAsync(int id)
        {
            return await _taskRepository.GetByIdAsync(id);
        }
        
        public async Task<TaskItem> CreateTaskAsync(TaskItem task)
        {
            var createdTask = await _taskRepository.CreateAsync(task);
            
            // Trigger event for high priority tasks
            if (createdTask.IsHighPriority())
            {
                await _eventPublisher.PublishHighPriorityTaskEventAsync(createdTask, "Created");
            }
            
            return createdTask;
        }
        
        public async Task<TaskItem?> UpdateTaskAsync(int id, TaskItem updatedTask)
        {
            var existingTask = await _taskRepository.GetByIdAsync(id);
            if (existingTask == null)
                return null;
                
            var wasHighPriority = existingTask.IsHighPriority();
            
            // Update the task
            updatedTask.Id = id;
            updatedTask.CreatedAt = existingTask.CreatedAt;
            
            var result = await _taskRepository.UpdateAsync(updatedTask);
            
            // Trigger event for high priority tasks (new high priority or was high priority)
            if (result != null && (result.IsHighPriority() || wasHighPriority))
            {
                await _eventPublisher.PublishHighPriorityTaskEventAsync(result, "Updated");
            }
            
            return result;
        }
        
        public async Task<bool> DeleteTaskAsync(int id)
        {
            return await _taskRepository.DeleteAsync(id);
        }
    }
}
