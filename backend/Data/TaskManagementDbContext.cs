using Microsoft.EntityFrameworkCore;
using backend.Models;
using TaskStatus = backend.Models.TaskStatus;

namespace backend.Data
{
    public class TaskManagementDbContext : DbContext
    {
        public TaskManagementDbContext(DbContextOptions<TaskManagementDbContext> options)
            : base(options)
        {
        }

        public DbSet<TaskItem> Tasks { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure TaskItem entity
            modelBuilder.Entity<TaskItem>(entity =>
            {
                // Table name
                entity.ToTable("Tasks");

                // Primary key
                entity.HasKey(e => e.Id);

                // Configure properties
                entity.Property(e => e.Title)
                    .IsRequired()
                    .HasMaxLength(200)
                    .HasColumnType("nvarchar(200)");

                entity.Property(e => e.Description)
                    .HasMaxLength(1000)
                    .HasColumnType("nvarchar(1000)");

                entity.Property(e => e.Priority)
                    .IsRequired()
                    .HasConversion<int>(); // Store enum as int

                entity.Property(e => e.Status)
                    .IsRequired()
                    .HasConversion<int>(); // Store enum as int

                entity.Property(e => e.DueDate)
                    .IsRequired()
                    .HasColumnType("datetime2");

                // BaseEntity properties
                entity.Property(e => e.CreatedAt)
                    .IsRequired()
                    .HasColumnType("datetime2")
                    .HasDefaultValueSql("GETUTCDATE()");

                // Indexes for performance
                entity.HasIndex(e => e.Status)
                    .HasDatabaseName("IX_Tasks_Status");

                entity.HasIndex(e => e.Priority)
                    .HasDatabaseName("IX_Tasks_Priority");

                entity.HasIndex(e => e.DueDate)
                    .HasDatabaseName("IX_Tasks_DueDate");

                entity.HasIndex(e => e.CreatedAt)
                    .HasDatabaseName("IX_Tasks_CreatedAt");
            });

            // Seed data
            modelBuilder.Entity<TaskItem>().HasData(
                new TaskItem
                {
                    Id = 1,
                    Title = "Welcome Task",
                    Description = "This is a sample task to get you started",
                    Priority = TaskPriority.Medium,
                    Status = TaskStatus.Pending,
                    DueDate = DateTime.UtcNow.AddDays(7),
                    CreatedAt = DateTime.UtcNow
                }
            );
        }

        // Override SaveChanges to automatically set audit fields
        public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            UpdateAuditFields();
            return await base.SaveChangesAsync(cancellationToken);
        }

        public override int SaveChanges()
        {
            UpdateAuditFields();
            return base.SaveChanges();
        }

        private void UpdateAuditFields()
        {
            var entries = ChangeTracker.Entries<BaseEntity>();

            foreach (var entry in entries)
            {
                switch (entry.State)
                {
                    case EntityState.Added:
                        entry.Entity.CreatedAt = DateTime.UtcNow;
                        break;

                    case EntityState.Modified:
                        entry.Entity.UpdatedAt = DateTime.UtcNow;
                        break;
                }
            }
        }
    }
}
