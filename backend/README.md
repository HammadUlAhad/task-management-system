# Task Management System - Backend API

A clean, best-practice RESTful API built with ASP.NET Core 8 and Entity Framework Core for efficient task management.

## 🚀 Features

- **Essential CRUD Operations**: Create, read, update, delete tasks
- **Priority Management**: Low, Medium, High priority levels  
- **Status Tracking**: Pending, In Progress, Completed, Archived
- **Request Logging**: Custom middleware for API request logging
- **Event System**: High-priority task event notifications
- **Entity Framework Core**: LocalDB persistence with clean migrations
- **Repository Pattern**: Clean architecture implementation
- **Best Practice Structure**: Minimal, essential fields only
- **Swagger Documentation**: Interactive API documentation

## 🏗️ Architecture

```
backend/
├── Controllers/         # API Controllers (clean CRUD endpoints)
├── Data/               # DbContext and database configuration
├── DTOs/               # Data Transfer Objects (best practice structure)
├── Middleware/         # Custom request logging middleware
├── Models/             # Clean domain entities (essential fields only)
├── Repositories/       # Data access layer
├── Services/           # Business logic layer
└── Configuration/      # Application configuration
```

## 📦 Dependencies

- **ASP.NET Core 8.0**
- **Entity Framework Core 8.0**
- **Microsoft.EntityFrameworkCore.SqlServer**
- **Swashbuckle.AspNetCore** (Swagger/OpenAPI)

## 🔧 Setup & Installation

1. **Prerequisites**
   ```bash
   .NET 8 SDK
   SQL Server LocalDB
   ```

2. **Clone and Build**
   ```bash
   cd backend
   dotnet restore
   dotnet build
   ```

3. **Database Setup**
   ```bash
   # Install EF Core CLI tools
   dotnet tool install --global dotnet-ef
   
   # Update database (migration already exists)
   dotnet ef database update
   ```

4. **Run the Application**
   ```bash
   dotnet run
   ```

5. **Access API Documentation**
   - Navigate to `https://localhost:7079/swagger` or `http://localhost:5192/swagger`
   - Swagger UI will be displayed

## 📋 API Endpoints (Essential CRUD Only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/tasks` | Retrieve all tasks |
| GET | `/tasks/{id}` | Retrieve a specific task |
| POST | `/tasks` | Create a new task |
| PUT | `/tasks/{id}` | Update a specific task |
| DELETE | `/tasks/{id}` | Delete a specific task |

## 🔍 Request/Response Examples

### Create Task
```json
POST /tasks
{
  "title": "Complete project documentation",
  "description": "Write comprehensive documentation",
  "priority": 2,
  "dueDate": "2025-08-20T10:00:00Z",
  "status": 0
}
```

### Response
```json
{
  "id": 1,
  "title": "Complete project documentation",
```

### Response (Best Practice Structure)
```json
{
  "id": 1,
  "title": "Complete project documentation",
  "description": "Write comprehensive documentation",
  "priority": 2,
  "dueDate": "2025-08-20T10:00:00Z",
  "status": 0,
  
  "isHighPriority": true,
  "isOverdue": false,
  "daysUntilDue": 7,
  
  "createdAt": "2025-08-13T10:30:00Z",
  "updatedAt": null
}
```

### Update Task
```json
PUT /tasks/1
{
  "title": "Updated task title",
  "description": "Updated description",
  "priority": 1,
  "dueDate": "2025-08-25T10:00:00Z",
  "status": 1
}
```

## 🛠️ Configuration

### Database Connection
Update `appsettings.json`:
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=TaskManagementDb;Trusted_Connection=true"
  }
}
```

### Logging
Logs are written to:
- `logs/api-requests.log` - All API requests
- `logs/critical-tasks.log` - High priority task events

## 🧪 Testing

Use the included `backend.http` file with VS Code REST Client extension to test all endpoints.

## 🔒 Security Features

- Input validation with custom error messages
- SQL injection prevention through EF Core
- Clean, minimal database schema
- Best practice data structure

## 📈 Performance Features

- Database indexes for optimized queries
- Async/await throughout the application
- Connection pooling ready
- Efficient LINQ queries
- Clean, lightweight entities

## 🌐 Environment Configuration

- **Development**: LocalDB with clean schema
- **Production**: SQL Server with optimized connection string

## ✨ Best Practices Implemented

- **Clean Architecture**: Repository and service patterns
- **Minimal Database Schema**: Only essential fields
- **API Response Structure**: Important fields first, timestamps last
- **SOLID Principles**: Dependency injection and separation of concerns
- **Entity Framework Best Practices**: Proper configuration and migrations
