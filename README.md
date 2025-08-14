# Advanced Task Management System

A full-stack task management application built with modern web technologies, featuring advanced functionality like lazy loading, real-time filtering, and comprehensive logging.

> **Quick Start**: Database is automatically created when you run `dotnet ef database update` - no manual setup required!

## What This Project Does

This task management system allows users to:

- **Create, Read, Update, Delete (CRUD) tasks** with comprehensive details
- **Filter tasks** by priority (Low, Medium, High) and status (Pending, In Progress, Completed, Archived)
- **Visual progress tracking** with dynamic charts and progress bars
- **Lazy loading** with infinite scroll for optimal performance
- **High priority confirmations** with warning modals
- **Detailed task management** with due dates and descriptions
- **Enterprise-grade logging** with custom middleware
- **Critical task monitoring** with separate high-priority event logging

## Project Structure

```
task-management-system/
├── backend/                    # ASP.NET Core 8 Web API
│   ├── Controllers/           # REST API controllers
│   │   └── TasksController.cs # Task CRUD operations with filtering & pagination
│   ├── Models/               # Domain models
│   │   ├── TaskItem.cs       # Main task entity
│   │   └── BaseEntity.cs     # Base entity with audit fields
│   ├── Services/             # Business logic layer
│   │   ├── TaskService.cs    # Task business operations
│   │   └── TaskEventPublisher.cs # High-priority task event handling
│   ├── Repositories/         # Data access layer
│   │   └── TaskRepository.cs # Task data operations
│   ├── DTOs/                 # Data transfer objects
│   │   └── TaskDtos.cs       # API request/response models
│   ├── Data/                 # Entity Framework context
│   │   └── TaskManagementDbContext.cs # Database context
│   ├── Middleware/           # Custom middleware
│   │   └── RequestLoggingMiddleware.cs # API request logging
│   ├── Migrations/           # Entity Framework migrations
│   ├── Configuration/        # Application configuration
│   └── logs/                 # Application log files
├── frontend/                  # Next.js 15 React Application
│   └── src/
│       ├── app/              # Next.js App Router pages
│       │   ├── page.tsx      # Home page with task list
│       │   ├── create/       # Create task page
│       │   └── tasks/[id]/   # Task detail and edit pages
│       ├── components/       # Reusable React components
│       │   └── TaskList.tsx  # Main task list with filtering & lazy loading
│       ├── services/         # API integration layer
│       │   └── taskApi.ts    # HTTP client for backend API
│       └── types/            # TypeScript type definitions
│           └── task.ts       # Task-related types
└── README.md                 # Project documentation
```

## Technologies & Versions

### Backend Stack
- **Framework**: ASP.NET Core 8.0
- **Language**: C# 12
- **Database**: SQL Server LocalDB (for local development)
- **ORM**: Entity Framework Core 8.0
- **Documentation**: Swagger/OpenAPI 3.0
- **Architecture**: Clean Architecture with Repository Pattern

### Frontend Stack
- **Framework**: Next.js 15.4.6 (App Router)
- **Language**: TypeScript 5.x
- **Runtime**: Node.js 18+
- **UI Library**: React 18+ with React Hooks
- **Styling**: Tailwind CSS 3.x
- **HTTP Client**: Axios
- **Icons**: Lucide React

### Development Tools
- **Build System**: .NET 8 SDK, npm/Node.js
- **Database**: SQL Server LocalDB
- **Version Control**: Git
- **IDE Support**: Visual Studio Code, Visual Studio

## Features Implemented

### Core Functionality
- [x] Complete CRUD operations for tasks
- [x] Task filtering by priority and status
- [x] Server-side pagination with lazy loading
- [x] Task detail view and editing
- [x] Responsive design for all devices

### Advanced Features
- [x] **Custom Middleware**: Logs every API request with details to file
- [x] **Event System**: Separate logging for high-priority task events
- [x] **Lazy Loading**: Infinite scroll with pagination (10 tasks per page)
- [x] **Visual Progress**: Dynamic progress bars showing task status distribution
- [x] **High Priority Modal**: Confirmation dialog for high-priority tasks
- [x] **Real-time Filtering**: Client-side filter application with server-side data

### Architecture Highlights
- [x] Repository Pattern for data access
- [x] Service Layer for business logic
- [x] DTO Pattern for API boundaries
- [x] Dependency Injection throughout
- [x] Async/await for non-blocking operations
- [x] Proper error handling and logging

## How to Run Locally

### Prerequisites
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [Node.js 18+](https://nodejs.org/)
- [SQL Server LocalDB](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/sql-server-express-localdb) (included with Visual Studio)

### Backend Setup

1. **Navigate to backend directory**:
   ```bash
   cd backend
   ```

2. **Restore dependencies**:
   ```bash
   dotnet restore
   ```

3. **Set up the database**:
   
   **First time setup** - Create and initialize the database:
   ```bash
   dotnet ef database update
   ```
   
   > **Note**: This command will:
   > - Create a new SQL Server LocalDB database named `TaskManagementDB`
   > - Apply all migrations to create the required tables (`Tasks` table)
   > - The database file will be created in your user directory
   > - No manual database setup required!

4. **Run the backend**:
   ```bash
   dotnet run
   ```
   
   Backend will be available at: `http://localhost:5192`
   
   Swagger documentation: `http://localhost:5192/swagger`

### Frontend Setup

1. **Navigate to frontend directory**:
   ```bash
   cd frontend
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Run the frontend**:
   ```bash
   npm run dev
   ```
   
   Frontend will be available at: `http://localhost:3000` (or next available port)

### Quick Start (Both Servers)

For development, run both servers simultaneously:

**Terminal 1 (Backend)**:
```bash
cd backend && dotnet run
```

**Terminal 2 (Frontend)**:
```bash
cd frontend && npm run dev
```

## Troubleshooting

### Database Issues

**If `dotnet ef database update` fails:**

1. **Install EF Core tools globally** (if not already installed):
   ```bash
   dotnet tool install --global dotnet-ef
   ```

2. **Check if SQL Server LocalDB is installed:**
   ```bash
   sqllocaldb info
   ```
   If not installed, download from [Microsoft SQL Server Express](https://www.microsoft.com/en-us/sql-server/sql-server-downloads)

3. **Reset database** (if corrupted):
   ```bash
   dotnet ef database drop
   dotnet ef database update
   ```

**If connection fails:**
- Ensure LocalDB is running: `sqllocaldb start MSSQLLocalDB`
- Check connection string in `appsettings.json`

### Common Issues

- **Port conflicts**: Backend uses port 5192, frontend uses port 3000
- **CORS errors**: Make sure backend is running before starting frontend
- **Build errors**: Run `dotnet clean` and `dotnet build` in backend directory

## API Documentation

Once the backend is running, visit `http://localhost:5192/swagger` for interactive API documentation.

### Key Endpoints
- `GET /api/tasks` - Get all tasks (with optional filtering and pagination)
- `GET /api/tasks/{id}` - Get specific task
- `POST /api/tasks` - Create new task
- `PUT /api/tasks/{id}` - Update existing task
- `DELETE /api/tasks/{id}` - Delete task

### Query Parameters
- `priority`: Filter by priority (Low, Medium, High)
- `status`: Filter by status (Pending, InProgress, Completed, Archived)
- `page`: Page number for pagination (default: 1)
- `pageSize`: Number of items per page (default: 10)

## Configuration

### Backend Configuration (`appsettings.json`)
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=TaskManagementDb;Trusted_Connection=true"
  },
  "Logging": {
    "RequestLogPath": "logs/api-requests.log",
    "CriticalTasksLogPath": "logs/critical-tasks.log"
  }
}
```

### Frontend Configuration
- API base URL is configured in `src/services/taskApi.ts`
- Tailwind CSS configuration in `tailwind.config.js`
- TypeScript configuration in `tsconfig.json`

## Database Schema

The application uses a single `Tasks` table with the following structure:

```sql
Tasks
├── Id (int, PK, Identity)
├── Title (nvarchar(200), Required)
├── Description (nvarchar(1000), Required)
├── Priority (int) -- 0=Low, 1=Medium, 2=High
├── Status (int) -- 0=Pending, 1=InProgress, 2=Completed, 3=Archived
├── DueDate (datetime2, Nullable)
├── CreatedAt (datetime2)
└── UpdatedAt (datetime2)
```

## Logging

The application includes comprehensive logging:

- **API Requests**: All HTTP requests logged to `logs/api-requests.log`
- **Critical Tasks**: High-priority task events logged to `logs/critical-tasks.log`
- **Console Logging**: Development information in terminal output

## Deployment Notes

For production deployment:

1. **Backend**: Deploy to IIS, Azure App Service, or Docker container
2. **Frontend**: Deploy to Vercel, Netlify, or static hosting
3. **Database**: Migrate from LocalDB to SQL Server or Azure SQL Database
4. **Environment**: Update connection strings and API URLs for production

## Contributing

This project follows industry best practices:
- Clean Architecture principles
- SOLID design principles
- Repository and Service patterns
- Comprehensive error handling
- TypeScript for type safety
- Responsive design patterns

## License

This project is for educational and demonstration purposes.

## Enterprise Features

For enterprise-grade implementations including JWT authentication, comprehensive testing strategies, real-time features with SignalR, and production deployment patterns, see:

**[Bonus Implementation Guide](BONUS_IMPLEMENTATION_GUIDE.md)**

---

**Built with ❤️ using modern web technologies and industry best practices**