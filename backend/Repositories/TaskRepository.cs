using Microsoft.EntityFrameworkCore;
using backend.Data;
using backend.Models;
using TaskStatus = backend.Models.TaskStatus;

namespace backend.Repositories
{
    public interface ITaskRepository
    {
        Task<IEnumerable<TaskItem>> GetAllAsync(bool includeDeleted = false);
        Task<TaskItem?> GetByIdAsync(int id, bool includeDeleted = false);
        Task<TaskItem> CreateAsync(TaskItem task);
        Task<TaskItem?> UpdateAsync(TaskItem task);
        Task<bool> DeleteAsync(int id);
    }

    public class TaskRepository : ITaskRepository
    {
        private readonly TaskManagementDbContext _context;

        public TaskRepository(TaskManagementDbContext context)
        {
            _context = context;
        }

        public async Task<IEnumerable<TaskItem>> GetAllAsync(bool includeDeleted = false)
        {
            var query = _context.Tasks.AsQueryable();
            
            if (includeDeleted)
            {
                query = query.IgnoreQueryFilters();
            }

            return await query
                .OrderByDescending(t => t.CreatedAt)
                .ToListAsync();
        }

        public async Task<TaskItem?> GetByIdAsync(int id, bool includeDeleted = false)
        {
            var query = _context.Tasks.AsQueryable();
            
            if (includeDeleted)
            {
                query = query.IgnoreQueryFilters();
            }

            return await query.FirstOrDefaultAsync(t => t.Id == id);
        }

        public async Task<TaskItem> CreateAsync(TaskItem task)
        {
            _context.Tasks.Add(task);
            await _context.SaveChangesAsync();
            return task;
        }

        public async Task<TaskItem?> UpdateAsync(TaskItem task)
        {
            var existingTask = await _context.Tasks.FindAsync(task.Id);
            if (existingTask == null)
                return null;

            _context.Entry(existingTask).CurrentValues.SetValues(task);
            existingTask.UpdateTimestamp();
            
            await _context.SaveChangesAsync();
            return existingTask;
        }

        public async Task<bool> DeleteAsync(int id)
        {
            var task = await _context.Tasks.IgnoreQueryFilters().FirstOrDefaultAsync(t => t.Id == id);
            if (task == null)
                return false;

            _context.Tasks.Remove(task);
            await _context.SaveChangesAsync();
            return true;
        }
    }
}
