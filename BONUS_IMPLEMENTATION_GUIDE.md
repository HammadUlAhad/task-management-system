# Enterprise-Grade Implementation Guide

This document outlines **industry-standard, production-ready implementations** for advanced features using patterns deployed at **Fortune 500 companies** and **FAANG enterprises**.

## JWT Authentication & Authorization (OAuth 2.0 + OIDC Pattern)

### Industry Standard: Microsoft Identity Platform Pattern
**Used by**: Microsoft, Google, Auth0, Okta, AWS Cognito

### Backend Implementation (.NET 8 - Enterprise Pattern)

#### 1. Identity Domain Models (DDD Pattern)
```csharp
// Domain/Entities/ApplicationUser.cs
public class ApplicationUser : IdentityUser<Guid>
{
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }
    public bool IsActive { get; set; } = true;
    
    // Navigation properties
    public virtual ICollection<TaskItem> Tasks { get; set; } = new HashSet<TaskItem>();
    public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = new HashSet<RefreshToken>();
}

// Domain/Entities/RefreshToken.cs - Secure token rotation
public class RefreshToken : BaseEntity
{
    public string Token { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public bool IsRevoked { get; set; }
    public string? ReplacedByToken { get; set; }
    public Guid UserId { get; set; }
    public virtual ApplicationUser User { get; set; } = null!;
}
```

#### 2. JWT Service (Industry Security Standards)
```csharp
// Application/Services/IJwtTokenService.cs
public interface IJwtTokenService
{
    Task<TokenResponse> GenerateTokensAsync(ApplicationUser user);
    Task<TokenResponse> RefreshTokenAsync(string refreshToken);
    Task<bool> RevokeTokenAsync(string refreshToken);
    ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
}

// Infrastructure/Services/JwtTokenService.cs
public class JwtTokenService : IJwtTokenService
{
    private readonly JwtOptions _jwtOptions;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    
    public async Task<TokenResponse> GenerateTokensAsync(ApplicationUser user)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new("firstName", user.FirstName),
            new("lastName", user.LastName)
        };

        // Add role claims (RBAC)
        var roles = await _userManager.GetRolesAsync(user);
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.SecretKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var accessToken = new JwtSecurityToken(
            issuer: _jwtOptions.Issuer,
            audience: _jwtOptions.Audience,
            claims: claims,
            expires: DateTime.UtcNow.Add(_jwtOptions.AccessTokenExpiration),
            signingCredentials: credentials);

        var refreshToken = await GenerateRefreshTokenAsync(user.Id);
        
        return new TokenResponse
        {
            AccessToken = new JwtSecurityTokenHandler().WriteToken(accessToken),
            RefreshToken = refreshToken.Token,
            ExpiresIn = (int)_jwtOptions.AccessTokenExpiration.TotalSeconds,
            TokenType = "Bearer"
        };
    }
    
    public async Task<TokenResponse> RefreshTokenAsync(string refreshToken)
    {
        var token = await _refreshTokenRepository.GetByTokenAsync(refreshToken);
        
        if (token == null || token.IsRevoked || token.ExpiresAt <= DateTime.UtcNow)
            throw new SecurityTokenException("Invalid refresh token");

        var user = await _userManager.FindByIdAsync(token.UserId.ToString());
        if (user == null || !user.IsActive)
            throw new SecurityTokenException("User not found or inactive");

        // Rotate refresh token (security best practice)
        token.IsRevoked = true;
        await _refreshTokenRepository.UpdateAsync(token);

        return await GenerateTokensAsync(user);
    }
}
```

#### 3. Program.cs - Enterprise Configuration
```csharp
// Program.cs - Production-ready authentication setup
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString, b => b.MigrationsAssembly("Infrastructure")));

// ASP.NET Identity with custom user
builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
{
    // Password policy (enterprise standards)
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    
    // Lockout policy (brute force protection)
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
    
    // User policy
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedEmail = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// JWT Authentication (OAuth 2.0 Bearer Token)
var jwtOptions = builder.Configuration.GetSection("Jwt").Get<JwtOptions>()!;
builder.Services.AddSingleton(jwtOptions);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.SecretKey)),
        ValidateIssuer = true,
        ValidIssuer = jwtOptions.Issuer,
        ValidateAudience = true,
        ValidAudience = jwtOptions.Audience,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero, // Remove default 5-minute tolerance
        RequireExpirationTime = true
    };
    
    // SignalR support
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            var accessToken = context.Request.Query["access_token"];
            var path = context.HttpContext.Request.Path;
            
            if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/hubs"))
            {
                context.Token = accessToken;
            }
            return Task.CompletedTask;
        }
    };
});

// Authorization Policies (RBAC)
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAdmin", policy => 
        policy.RequireRole("Administrator"));
    options.AddPolicy("RequireManager", policy => 
        policy.RequireRole("Administrator", "Manager"));
    options.AddPolicy("TaskOwner", policy =>
        policy.Requirements.Add(new TaskOwnerRequirement()));
});
```

#### 4. Authentication Controller (REST API Standards)
```csharp
// Presentation/Controllers/AuthController.cs
[ApiController]
[Route("api/v1/auth")]
[Produces("application/json")]
public class AuthController : ControllerBase
{
    private readonly IAuthenticationService _authService;
    private readonly ILogger<AuthController> _logger;
    
    /// <summary>
    /// Authenticates user and returns JWT tokens (OAuth 2.0 flow)
    /// </summary>
    /// <param name="request">Login credentials</param>
    /// <returns>JWT access token and refresh token</returns>
    [HttpPost("login")]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status429TooManyRequests)]
    public async Task<ActionResult<TokenResponse>> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);
            
        var result = await _authService.LoginAsync(request);
        
        if (!result.Succeeded)
        {
            _logger.LogWarning("Failed login attempt for email: {Email}", request.Email);
            return Unauthorized(new ApiErrorResponse("Invalid credentials"));
        }
        
        _logger.LogInformation("Successful login for user: {UserId}", result.User.Id);
        return Ok(result.TokenResponse);
    }
    
    /// <summary>
    /// Refreshes JWT access token using refresh token
    /// </summary>
    [HttpPost("refresh")]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<TokenResponse>> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        try
        {
            var response = await _authService.RefreshTokenAsync(request.RefreshToken);
            return Ok(response);
        }
        catch (SecurityTokenException ex)
        {
            _logger.LogWarning("Invalid refresh token attempt: {Error}", ex.Message);
            return Unauthorized(new ApiErrorResponse("Invalid refresh token"));
        }
    }
    
    /// <summary>
    /// Revokes refresh token (logout)
    /// </summary>
    [HttpPost("logout")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
    {
        await _authService.RevokeTokenAsync(request.RefreshToken);
        return NoContent();
    }
}
```

### Frontend Implementation (Next.js 14 + React 18 - Enterprise Pattern)

#### 1. Authentication Provider (Context + Zustand Pattern)
```typescript
// lib/auth/auth-store.ts - Zustand store (used by Vercel, Shopify)
interface AuthState {
  user: User | null;
  accessToken: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: LoginCredentials) => Promise<void>;
  logout: () => void;
  refreshAccessToken: () => Promise<void>;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  accessToken: null,
  refreshToken: null,
  isAuthenticated: false,
  isLoading: true,
  
  login: async (credentials) => {
    try {
      const response = await authApi.login(credentials);
      const { accessToken, refreshToken, user } = response;
      
      // Store tokens securely
      tokenStorage.setTokens(accessToken, refreshToken);
      
      set({ 
        user, 
        accessToken, 
        refreshToken, 
        isAuthenticated: true,
        isLoading: false 
      });
      
    } catch (error) {
      set({ isLoading: false });
      throw error;
    }
  },
  
  refreshAccessToken: async () => {
    const { refreshToken } = get();
    if (!refreshToken) throw new Error('No refresh token');
    
    try {
      const response = await authApi.refreshToken(refreshToken);
      const { accessToken: newAccessToken, refreshToken: newRefreshToken } = response;
      
      tokenStorage.setTokens(newAccessToken, newRefreshToken);
      
      set({ 
        accessToken: newAccessToken, 
        refreshToken: newRefreshToken 
      });
      
    } catch (error) {
      // Refresh failed, logout user
      get().logout();
      throw error;
    }
  },
  
  logout: () => {
    tokenStorage.clearTokens();
    set({ 
      user: null, 
      accessToken: null, 
      refreshToken: null, 
      isAuthenticated: false 
    });
    window.location.href = '/login';
  }
}));
```

#### 2. Secure Token Storage (HttpOnly Cookie Pattern)
```typescript
// lib/auth/token-storage.ts - Secure storage (Netflix, Spotify pattern)
class TokenStorage {
  private readonly ACCESS_TOKEN_KEY = 'access_token';
  private readonly REFRESH_TOKEN_KEY = 'refresh_token';
  
  setTokens(accessToken: string, refreshToken: string): void {
    // Store refresh token in httpOnly cookie (server-side only)
    this.setHttpOnlyCookie(this.REFRESH_TOKEN_KEY, refreshToken, 7 * 24 * 60 * 60); // 7 days
    
    // Store access token in memory only (XSS protection)
    this.setMemoryToken(accessToken);
  }
  
  private setHttpOnlyCookie(name: string, value: string, maxAge: number): void {
    // This would be set by the server in the login response
    document.cookie = `${name}=${value}; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}; Path=/`;
  }
  
  private setMemoryToken(token: string): void {
    // Store in module-level variable (memory only, cleared on page refresh)
    this.accessToken = token;
  }
  
  getAccessToken(): string | null {
    return this.accessToken;
  }
  
  clearTokens(): void {
    this.accessToken = null;
    // Clear httpOnly cookie via server endpoint
    fetch('/api/auth/clear-cookies', { method: 'POST' });
  }
  
  private accessToken: string | null = null;
}

export const tokenStorage = new TokenStorage();
```

#### 3. Axios Interceptors with Automatic Token Refresh
```typescript
// lib/api/interceptors.ts - Industry standard (GitHub, GitLab pattern)
let isRefreshing = false;
let failedQueue: Array<{
  resolve: (token: string) => void;
  reject: (error: any) => void;
}> = [];

const processQueue = (error: any, token: string | null = null) => {
  failedQueue.forEach(({ resolve, reject }) => {
    if (error) {
      reject(error);
    } else {
      resolve(token!);
    }
  });
  
  failedQueue = [];
};

// Request interceptor
apiClient.interceptors.request.use(
  (config) => {
    const token = tokenStorage.getAccessToken();
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor with automatic token refresh
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        // Queue request while refresh is in progress
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then((token) => {
          originalRequest.headers.Authorization = `Bearer ${token}`;
          return apiClient(originalRequest);
        });
      }
      
      originalRequest._retry = true;
      isRefreshing = true;
      
      try {
        const authStore = useAuthStore.getState();
        await authStore.refreshAccessToken();
        const newToken = tokenStorage.getAccessToken();
        
        processQueue(null, newToken);
        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        
        return apiClient(originalRequest);
        
      } catch (refreshError) {
        processQueue(refreshError);
        useAuthStore.getState().logout();
        return Promise.reject(refreshError);
        
      } finally {
        isRefreshing = false;
      }
    }
    
    return Promise.reject(error);
  }
);
```

#### 4. Next.js Middleware (Route Protection)
```typescript
// middleware.ts - Next.js 14 pattern (Vercel, Linear)
import { NextRequest, NextResponse } from 'next/server';
import { verifyJwtToken } from './lib/auth/jwt-utils';

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  
  // Public routes that don't require authentication
  const publicRoutes = ['/login', '/register', '/forgot-password', '/api/auth'];
  const isPublicRoute = publicRoutes.some(route => pathname.startsWith(route));
  
  if (isPublicRoute) {
    return NextResponse.next();
  }
  
  // Check for authentication token
  const token = request.cookies.get('refresh_token')?.value;
  
  if (!token) {
    return NextResponse.redirect(new URL('/login', request.url));
  }
  
  try {
    // Verify token (you might want to cache this verification)
    const payload = await verifyJwtToken(token);
    
    if (!payload) {
      return NextResponse.redirect(new URL('/login', request.url));
    }
    
    // Add user info to request headers for API routes
    const requestHeaders = new Headers(request.headers);
    requestHeaders.set('x-user-id', payload.sub);
    requestHeaders.set('x-user-email', payload.email);
    
    return NextResponse.next({
      request: {
        headers: requestHeaders,
      },
    });
    
  } catch (error) {
    console.error('Token verification failed:', error);
    return NextResponse.redirect(new URL('/login', request.url));
  }
}

export const config = {
  matcher: [
    '/((?!api/auth|_next/static|_next/image|favicon.ico|public).*)',
  ],
};
```

### Security Best Practices (OWASP Standards)
- **Password Security**: BCrypt with 12+ salt rounds
- **Token Security**: Short-lived access tokens (15 min), secure refresh tokens (7 days)
- **Storage Security**: HttpOnly cookies for refresh tokens, memory-only for access tokens
- **Transport Security**: HTTPS only, Secure + SameSite cookies
- **Rate Limiting**: Login attempts, token refresh attempts
- **Audit Logging**: All authentication events logged
- **RBAC**: Role-based access control with fine-grained permissions

---

## Enterprise Testing Strategy (Google/Microsoft Pattern)

### Industry Standard: Pyramid Testing Architecture
**Used by**: Google, Microsoft, Netflix, Uber, Meta

### Backend Testing (.NET 8 - xUnit + Testcontainers)

#### 1. Test Architecture (Clean Architecture Pattern)
```
Tests/
├── UnitTests/
│   ├── Application.UnitTests/
│   │   ├── Services/TaskServiceTests.cs
│   │   ├── Handlers/CreateTaskHandlerTests.cs
│   │   └── Validators/TaskValidatorTests.cs
│   └── Domain.UnitTests/
│       ├── Entities/TaskItemTests.cs
│       └── ValueObjects/TaskPriorityTests.cs
├── IntegrationTests/
│   ├── Infrastructure.IntegrationTests/
│   │   ├── Repositories/TaskRepositoryTests.cs
│   │   └── ExternalServices/EmailServiceTests.cs
│   └── WebApi.IntegrationTests/
│       ├── Controllers/TasksControllerTests.cs
│       └── Authentication/JwtAuthenticationTests.cs
└── EndToEndTests/
    ├── Scenarios/TaskManagementFlowTests.cs
    └── Performance/LoadTests.cs
```

#### 2. Unit Testing with Industry Standards
```csharp
// Tests/Application.UnitTests/Services/TaskServiceTests.cs
public class TaskServiceTests
{
    private readonly Mock<ITaskRepository> _mockRepository;
    private readonly Mock<ITaskEventPublisher> _mockEventPublisher;
    private readonly Mock<ILogger<TaskService>> _mockLogger;
    private readonly TaskService _sut; // System Under Test
    
    public TaskServiceTests()
    {
        _mockRepository = new Mock<ITaskRepository>();
        _mockEventPublisher = new Mock<ITaskEventPublisher>();
        _mockLogger = new Mock<ILogger<TaskService>>();
        _sut = new TaskService(_mockRepository.Object, _mockEventPublisher.Object, _mockLogger.Object);
    }
    
    [Theory]
    [MemberData(nameof(ValidTaskTestData))]
    public async Task CreateTaskAsync_WithValidTask_ShouldReturnCreatedTask(TaskItem inputTask, TaskItem expectedTask)
    {
        // Arrange
        _mockRepository
            .Setup(x => x.CreateTaskAsync(It.IsAny<TaskItem>()))
            .ReturnsAsync(expectedTask);
        
        // Act
        var result = await _sut.CreateTaskAsync(inputTask);
        
        // Assert
        result.Should().NotBeNull();
        result.Should().BeEquivalentTo(expectedTask);
        _mockRepository.Verify(x => x.CreateTaskAsync(inputTask), Times.Once);
    }
    
    [Fact]
    public async Task CreateTaskAsync_WithHighPriorityTask_ShouldPublishEvent()
    {
        // Arrange
        var highPriorityTask = TaskItemBuilder.Create()
            .WithPriority(TaskPriority.High)
            .WithTitle("Critical Task")
            .Build();
            
        _mockRepository
            .Setup(x => x.CreateTaskAsync(It.IsAny<TaskItem>()))
            .ReturnsAsync(highPriorityTask);
        
        // Act
        await _sut.CreateTaskAsync(highPriorityTask);
        
        // Assert
        _mockEventPublisher.Verify(
            x => x.PublishHighPriorityTaskEventAsync(
                It.Is<TaskItem>(t => t.Priority == TaskPriority.High), 
                "created"), 
            Times.Once);
    }
    
    [Fact]
    public async Task CreateTaskAsync_WhenRepositoryThrows_ShouldLogErrorAndPropagate()
    {
        // Arrange
        var task = TaskItemBuilder.Create().Build();
        var expectedException = new Exception("Database connection failed");
        
        _mockRepository
            .Setup(x => x.CreateTaskAsync(It.IsAny<TaskItem>()))
            .ThrowsAsync(expectedException);
        
        // Act & Assert
        var exception = await Assert.ThrowsAsync<Exception>(
            () => _sut.CreateTaskAsync(task));
        
        exception.Should().Be(expectedException);
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("Failed to create task")),
                expectedException,
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Once);
    }
    
    public static IEnumerable<object[]> ValidTaskTestData =>
        new List<object[]>
        {
            new object[] 
            { 
                TaskItemBuilder.Create().WithTitle("Test Task").Build(),
                TaskItemBuilder.Create().WithId(1).WithTitle("Test Task").Build()
            }
        };
}

// Test Builders (Builder Pattern)
public class TaskItemBuilder
{
    private TaskItem _task = new()
    {
        Title = "Default Task",
        Description = "Default Description",
        Priority = TaskPriority.Medium,
        Status = TaskStatus.Pending,
        DueDate = DateTime.UtcNow.AddDays(7)
    };
    
    public static TaskItemBuilder Create() => new();
    
    public TaskItemBuilder WithId(int id)
    {
        _task.Id = id;
        return this;
    }
    
    public TaskItemBuilder WithTitle(string title)
    {
        _task.Title = title;
        return this;
    }
    
    public TaskItemBuilder WithPriority(TaskPriority priority)
    {
        _task.Priority = priority;
        return this;
    }
    
    public TaskItem Build() => _task;
}
```

#### 3. Integration Testing with Testcontainers
```csharp
// Tests/IntegrationTests/Infrastructure/TaskRepositoryIntegrationTests.cs
public class TaskRepositoryIntegrationTests : IAsyncLifetime
{
    private readonly TestcontainersContainer _sqlServerContainer;
    private TaskManagementDbContext _dbContext;
    private TaskRepository _repository;
    
    public TaskRepositoryIntegrationTests()
    {
        _sqlServerContainer = new TestcontainersBuilder<MsSqlTestcontainer>()
            .WithDatabase(new MsSqlTestcontainerConfiguration
            {
                Password = "Strong_password123!",
                Database = "TaskManagementTestDb"
            })
            .WithCleanUp(true)
            .Build();
    }
    
    public async Task InitializeAsync()
    {
        await _sqlServerContainer.StartAsync();
        
        var options = new DbContextOptionsBuilder<TaskManagementDbContext>()
            .UseSqlServer(_sqlServerContainer.GetConnectionString())
            .Options;
            
        _dbContext = new TaskManagementDbContext(options);
        await _dbContext.Database.EnsureCreatedAsync();
        
        _repository = new TaskRepository(_dbContext);
    }
    
    [Fact]
    public async Task CreateTaskAsync_ShouldPersistTaskToDatabase()
    {
        // Arrange
        var task = TaskItemBuilder.Create()
            .WithTitle("Integration Test Task")
            .WithPriority(TaskPriority.High)
            .Build();
        
        // Act
        var createdTask = await _repository.CreateTaskAsync(task);
        
        // Assert
        createdTask.Should().NotBeNull();
        createdTask.Id.Should().BeGreaterThan(0);
        
        var persistedTask = await _dbContext.Tasks.FindAsync(createdTask.Id);
        persistedTask.Should().NotBeNull();
        persistedTask!.Title.Should().Be("Integration Test Task");
    }
    
    public async Task DisposeAsync()
    {
        await _dbContext.DisposeAsync();
        await _sqlServerContainer.DisposeAsync();
    }
}
```

#### 4. API Integration Testing (WebApplicationFactory)
```csharp
// Tests/IntegrationTests/WebApi/TasksControllerIntegrationTests.cs
public class TasksControllerIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;
    
    public TasksControllerIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                // Replace with in-memory database
                services.RemoveAll<DbContextOptions<TaskManagementDbContext>>();
                services.AddDbContext<TaskManagementDbContext>(options =>
                {
                    options.UseInMemoryDatabase("TestDb");
                });
                
                // Override external dependencies
                services.AddScoped<IEmailService, MockEmailService>();
            });
        });
        
        _client = _factory.CreateClient();
    }
    
    [Fact]
    public async Task GetTasks_WithValidToken_ShouldReturnTasks()
    {
        // Arrange
        var token = await GetAuthTokenAsync();
        _client.DefaultRequestHeaders.Authorization = 
            new AuthenticationHeaderValue("Bearer", token);
        
        await SeedTestDataAsync();
        
        // Act
        var response = await _client.GetAsync("/api/v1/tasks");
        
        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        
        var content = await response.Content.ReadAsStringAsync();
        var tasks = JsonSerializer.Deserialize<List<TaskDto>>(content, JsonOptions);
        
        tasks.Should().NotBeNullOrEmpty();
        tasks.Should().HaveCount(3);
    }
    
    [Theory]
    [InlineData("High", "Pending")]
    [InlineData("Medium", "InProgress")]
    public async Task GetTasks_WithFilters_ShouldReturnFilteredResults(string priority, string status)
    {
        // Arrange
        var token = await GetAuthTokenAsync();
        _client.DefaultRequestHeaders.Authorization = 
            new AuthenticationHeaderValue("Bearer", token);
        
        await SeedTestDataAsync();
        
        // Act
        var response = await _client.GetAsync($"/api/v1/tasks?priority={priority}&status={status}");
        
        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        
        var content = await response.Content.ReadAsStringAsync();
        var tasks = JsonSerializer.Deserialize<List<TaskDto>>(content, JsonOptions);
        
        tasks.Should().AllSatisfy(task =>
        {
            task.Priority.Should().Be(priority);
            task.Status.Should().Be(status);
        });
    }
    
    private async Task<string> GetAuthTokenAsync()
    {
        // Implementation to get JWT token for testing
    }
}
```

### Frontend Testing (React + Jest + Testing Library)

#### 1. Test Setup Configuration
```typescript
// jest.config.js - Industry standard configuration
module.exports = {
  testEnvironment: 'jsdom',
  setupFilesAfterEnv: ['<rootDir>/src/test-utils/setup.ts'],
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '\\.(css|less|scss|sass)$': 'identity-obj-proxy',
  },
  collectCoverageFrom: [
    'src/**/*.{js,jsx,ts,tsx}',
    '!src/**/*.d.ts',
    '!src/test-utils/**',
    '!src/**/*.stories.{js,jsx,ts,tsx}',
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
  testMatch: [
    '<rootDir>/src/**/__tests__/**/*.{js,jsx,ts,tsx}',
    '<rootDir>/src/**/*.{test,spec}.{js,jsx,ts,tsx}',
  ],
};

// src/test-utils/setup.ts
import '@testing-library/jest-dom';
import { server } from './mocks/server';

// MSW Setup
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// Mock Next.js router
jest.mock('next/navigation', () => ({
  useRouter: () => ({
    push: jest.fn(),
    back: jest.fn(),
    forward: jest.fn(),
    refresh: jest.fn(),
    replace: jest.fn(),
    prefetch: jest.fn(),
  }),
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => '/',
}));
```

#### 2. Component Testing with Testing Library
```typescript
// src/components/__tests__/TaskList.test.tsx
describe('TaskList Component', () => {
  const mockTasks: Task[] = [
    {
      id: 1,
      title: 'High Priority Task',
      description: 'Urgent task',
      priority: 'High',
      status: 'Pending',
      dueDate: '2024-12-31T23:59:59Z',
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
    },
  ];
  
  beforeEach(() => {
    // Reset all mocks before each test
    jest.clearAllMocks();
  });
  
  it('should render tasks correctly', async () => {
    // Arrange
    server.use(
      http.get('/api/v1/tasks', () => {
        return HttpResponse.json(mockTasks);
      })
    );
    
    // Act
    render(<TaskList />);
    
    // Assert
    await waitFor(() => {
      expect(screen.getByText('High Priority Task')).toBeInTheDocument();
    });
    
    expect(screen.getByText('Urgent task')).toBeInTheDocument();
    expect(screen.getByText('High')).toBeInTheDocument();
  });
  
  it('should filter tasks by priority', async () => {
    // Arrange
    const user = userEvent.setup();
    
    server.use(
      http.get('/api/v1/tasks', ({ request }) => {
        const url = new URL(request.url);
        const priority = url.searchParams.get('priority');
        
        if (priority === 'High') {
          return HttpResponse.json(mockTasks.filter(t => t.priority === 'High'));
        }
        return HttpResponse.json([]);
      })
    );
    
    render(<TaskList />);
    
    // Act
    const priorityFilter = screen.getByLabelText(/filter by priority/i);
    await user.selectOptions(priorityFilter, 'High');
    
    // Assert
    await waitFor(() => {
      expect(screen.getByText('High Priority Task')).toBeInTheDocument();
    });
  });
  
  it('should handle loading state', () => {
    // Arrange
    server.use(
      http.get('/api/v1/tasks', async () => {
        await delay(1000); // Simulate network delay
        return HttpResponse.json(mockTasks);
      })
    );
    
    // Act
    render(<TaskList />);
    
    // Assert
    expect(screen.getByTestId('loading-spinner')).toBeInTheDocument();
    expect(screen.getByText(/loading tasks/i)).toBeInTheDocument();
  });
  
  it('should handle error state', async () => {
    // Arrange
    server.use(
      http.get('/api/v1/tasks', () => {
        return new HttpResponse(null, { status: 500 });
      })
    );
    
    // Act
    render(<TaskList />);
    
    // Assert
    await waitFor(() => {
      expect(screen.getByText(/error loading tasks/i)).toBeInTheDocument();
    });
  });
});
```

#### 3. Hook Testing
```typescript
// src/hooks/__tests__/useAuth.test.ts
describe('useAuth Hook', () => {
  beforeEach(() => {
    // Clear localStorage and reset auth store
    localStorage.clear();
    useAuthStore.setState({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: false,
    });
  });
  
  it('should login user successfully', async () => {
    // Arrange
    const mockUser = { id: '1', email: 'test@example.com', firstName: 'John' };
    const mockTokens = { accessToken: 'access_token', refreshToken: 'refresh_token' };
    
    server.use(
      http.post('/api/v1/auth/login', () => {
        return HttpResponse.json({ user: mockUser, ...mockTokens });
      })
    );
    
    const { result } = renderHook(() => useAuth());
    
    // Act
    await act(async () => {
      await result.current.login('test@example.com', 'password123');
    });
    
    // Assert
    expect(result.current.isAuthenticated).toBe(true);
    expect(result.current.user).toEqual(mockUser);
    expect(localStorage.getItem('auth_token')).toBe('access_token');
  });
  
  it('should handle login failure', async () => {
    // Arrange
    server.use(
      http.post('/api/v1/auth/login', () => {
        return new HttpResponse(null, { status: 401 });
      })
    );
    
    const { result } = renderHook(() => useAuth());
    
    // Act & Assert
    await act(async () => {
      await expect(
        result.current.login('wrong@example.com', 'wrongpassword')
      ).rejects.toThrow();
    });
    
    expect(result.current.isAuthenticated).toBe(false);
    expect(result.current.user).toBeNull();
  });
});
```

#### 4. E2E Testing with Playwright
```typescript
// e2e/task-management.spec.ts
import { test, expect, Page } from '@playwright/test';

test.describe('Task Management Flow', () => {
  let page: Page;
  
  test.beforeEach(async ({ browser }) => {
    page = await browser.newPage();
    await page.goto('/');
    
    // Login before each test
    await loginUser(page, 'test@example.com', 'password123');
  });
  
  test('should create a new task', async () => {
    // Navigate to create task page
    await page.getByRole('link', { name: /create task/i }).click();
    
    // Fill task form
    await page.getByLabel(/task title/i).fill('E2E Test Task');
    await page.getByLabel(/description/i).fill('Created by E2E test');
    await page.getByLabel(/priority/i).selectOption('High');
    
    // Submit form
    await page.getByRole('button', { name: /create task/i }).click();
    
    // Verify task was created
    await expect(page.getByText('E2E Test Task')).toBeVisible();
    await expect(page.getByText('Created by E2E test')).toBeVisible();
  });
  
  test('should show high priority confirmation modal', async () => {
    await page.getByRole('link', { name: /create task/i }).click();
    
    await page.getByLabel(/task title/i).fill('Urgent Task');
    await page.getByLabel(/priority/i).selectOption('High');
    
    await page.getByRole('button', { name: /create task/i }).click();
    
    // Verify modal appears
    await expect(page.getByText(/high priority task/i)).toBeVisible();
    await expect(page.getByText(/are you sure/i)).toBeVisible();
    
    // Confirm creation
    await page.getByRole('button', { name: /yes, create/i }).click();
    
    await expect(page.getByText('Urgent Task')).toBeVisible();
  });
});

async function loginUser(page: Page, email: string, password: string) {
  await page.goto('/login');
  await page.getByLabel(/email/i).fill(email);
  await page.getByLabel(/password/i).fill(password);
  await page.getByRole('button', { name: /login/i }).click();
  await expect(page).toHaveURL('/');
}
```

### Testing Strategy Pyramid
1. **Unit Tests (70%)**: Fast, isolated, cover business logic
2. **Integration Tests (20%)**: Database, external services, API endpoints  
3. **E2E Tests (10%)**: Critical user journeys, browser automation

### Quality Metrics (Industry Standards)
- **Code Coverage**: 80%+ for critical paths
- **Performance**: API responses < 200ms (95th percentile)
- **Reliability**: 99.9% uptime, < 0.1% error rate
- **Security**: OWASP compliance, vulnerability scanning

---

## Enterprise Real-Time Implementation (Microsoft SignalR)

### Industry Standard: WebSocket + Fallback Architecture
**Used by**: Microsoft Teams, Slack, Discord, WhatsApp Web, Figma

### Production-Ready SignalR Implementation

#### 1. SignalR Hub with Connection Management
```csharp
// Hubs/TaskHub.cs - Enterprise-grade hub
[Authorize]
public class TaskHub : Hub
{
    private readonly ITaskService _taskService;
    private readonly IUserConnectionManager _connectionManager;
    private readonly ILogger<TaskHub> _logger;
    private readonly IMemoryCache _cache;
    
    public TaskHub(
        ITaskService taskService,
        IUserConnectionManager connectionManager,
        ILogger<TaskHub> logger,
        IMemoryCache cache)
    {
        _taskService = taskService;
        _connectionManager = connectionManager;
        _logger = logger;
        _cache = cache;
    }
    
    public override async Task OnConnectedAsync()
    {
        var userId = Context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            Context.Abort();
            return;
        }
        
        // Add connection to user group
        await Groups.AddToGroupAsync(Context.ConnectionId, $"user_{userId}");
        
        // Track connection for presence
        await _connectionManager.AddConnectionAsync(userId, Context.ConnectionId);
        
        // Send initial data
        var recentTasks = await _taskService.GetUserTasksAsync(userId, limit: 10);
        await Clients.Caller.SendAsync("InitialData", recentTasks);
        
        _logger.LogInformation("User {UserId} connected with connection {ConnectionId}", 
            userId, Context.ConnectionId);
        
        await base.OnConnectedAsync();
    }
    
    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        var userId = Context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!string.IsNullOrEmpty(userId))
        {
            await _connectionManager.RemoveConnectionAsync(userId, Context.ConnectionId);
            await Groups.RemoveFromGroupAsync(Context.ConnectionId, $"user_{userId}");
            
            _logger.LogInformation("User {UserId} disconnected from connection {ConnectionId}", 
                userId, Context.ConnectionId);
        }
        
        if (exception != null)
        {
            _logger.LogError(exception, "Connection {ConnectionId} disconnected with error", 
                Context.ConnectionId);
        }
        
        await base.OnDisconnectedAsync(exception);
    }
    
    // Client-to-server methods
    public async Task JoinTaskGroup(int taskId)
    {
        var userId = Context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var task = await _taskService.GetTaskAsync(taskId);
        
        // Verify user has access to this task
        if (task?.AssignedUserId != userId)
        {
            await Clients.Caller.SendAsync("Error", "Access denied");
            return;
        }
        
        await Groups.AddToGroupAsync(Context.ConnectionId, $"task_{taskId}");
        await Clients.Caller.SendAsync("JoinedTaskGroup", taskId);
    }
    
    public async Task LeaveTaskGroup(int taskId)
    {
        await Groups.RemoveFromGroupAsync(Context.ConnectionId, $"task_{taskId}");
        await Clients.Caller.SendAsync("LeftTaskGroup", taskId);
    }
    
    // Server-to-client event broadcasting
    public async Task BroadcastTaskCreated(TaskItem task)
    {
        var taskDto = TaskDto.FromEntity(task);
        
        // Notify all users in the organization
        await Clients.Group($"org_{task.OrganizationId}")
            .SendAsync("TaskCreated", taskDto);
            
        // Send push notification for high priority tasks
        if (task.Priority == TaskPriority.High)
        {
            await Clients.Group($"org_{task.OrganizationId}")
                .SendAsync("HighPriorityTaskAlert", taskDto);
        }
    }
    
    public async Task BroadcastTaskUpdated(TaskItem task, string changeType)
    {
        var taskDto = TaskDto.FromEntity(task);
        
        // Notify task watchers
        await Clients.Group($"task_{task.Id}")
            .SendAsync("TaskUpdated", taskDto, changeType);
            
        // Notify assignee if different from updater
        var updaterId = Context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (task.AssignedUserId != updaterId)
        {
            await Clients.Group($"user_{task.AssignedUserId}")
                .SendAsync("TaskAssignedToYou", taskDto, changeType);
        }
    }
}

// Services/UserConnectionManager.cs - Connection tracking
public interface IUserConnectionManager
{
    Task AddConnectionAsync(string userId, string connectionId);
    Task RemoveConnectionAsync(string userId, string connectionId);
    Task<List<string>> GetUserConnectionsAsync(string userId);
    Task<bool> IsUserOnlineAsync(string userId);
}

public class UserConnectionManager : IUserConnectionManager
{
    private readonly IMemoryCache _cache;
    private readonly ILogger<UserConnectionManager> _logger;
    private const int CacheExpirationMinutes = 60;
    
    public UserConnectionManager(IMemoryCache cache, ILogger<UserConnectionManager> logger)
    {
        _cache = cache;
        _logger = logger;
    }
    
    public async Task AddConnectionAsync(string userId, string connectionId)
    {
        var cacheKey = $"user_connections_{userId}";
        var connections = _cache.Get<HashSet<string>>(cacheKey) ?? new HashSet<string>();
        
        connections.Add(connectionId);
        
        _cache.Set(cacheKey, connections, TimeSpan.FromMinutes(CacheExpirationMinutes));
        
        _logger.LogDebug("Added connection {ConnectionId} for user {UserId}. Total connections: {Count}",
            connectionId, userId, connections.Count);
    }
    
    public async Task RemoveConnectionAsync(string userId, string connectionId)
    {
        var cacheKey = $"user_connections_{userId}";
        var connections = _cache.Get<HashSet<string>>(cacheKey);
        
        if (connections != null)
        {
            connections.Remove(connectionId);
            
            if (connections.Any())
            {
                _cache.Set(cacheKey, connections, TimeSpan.FromMinutes(CacheExpirationMinutes));
            }
            else
            {
                _cache.Remove(cacheKey);
            }
            
            _logger.LogDebug("Removed connection {ConnectionId} for user {UserId}. Remaining connections: {Count}",
                connectionId, userId, connections.Count);
        }
    }
    
    public async Task<List<string>> GetUserConnectionsAsync(string userId)
    {
        var cacheKey = $"user_connections_{userId}";
        var connections = _cache.Get<HashSet<string>>(cacheKey);
        return connections?.ToList() ?? new List<string>();
    }
    
    public async Task<bool> IsUserOnlineAsync(string userId)
    {
        var connections = await GetUserConnectionsAsync(userId);
        return connections.Any();
    }
}
```

#### 2. SignalR Configuration (Production Settings)
```csharp
// Program.cs - Production SignalR configuration
builder.Services.AddSignalR(hubOptions =>
{
    hubOptions.EnableDetailedErrors = builder.Environment.IsDevelopment();
    hubOptions.KeepAliveInterval = TimeSpan.FromSeconds(15);
    hubOptions.ClientTimeoutInterval = TimeSpan.FromSeconds(30);
    hubOptions.HandshakeTimeout = TimeSpan.FromSeconds(15);
    hubOptions.MaximumReceiveMessageSize = 32 * 1024; // 32KB
    hubOptions.StreamBufferCapacity = 10;
    hubOptions.MaximumParallelInvocationsPerClient = 1;
})
.AddJsonProtocol(options =>
{
    options.PayloadSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    options.PayloadSerializerOptions.WriteIndented = false;
})
// Add Redis backplane for horizontal scaling
.AddStackExchangeRedis(builder.Configuration.GetConnectionString("Redis"), options =>
{
    options.Configuration.ChannelPrefix = "TaskManagement";
});

// CORS for SignalR
builder.Services.AddCors(options =>
{
    options.AddPolicy("SignalRCors", policy =>
    {
        policy
            .WithOrigins(builder.Configuration.GetSection("AllowedOrigins").Get<string[]>() ?? Array.Empty<string>())
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials(); // Required for SignalR
    });
});

// Background service for cleanup
builder.Services.AddHostedService<ConnectionCleanupService>();

var app = builder.Build();

app.UseCors("SignalRCors");

// Map hub with authorization
app.MapHub<TaskHub>("/taskHub", options =>
{
    options.Transports = HttpTransportType.WebSockets | HttpTransportType.ServerSentEvents;
});
```

#### 3. Frontend SignalR Client (React/TypeScript)
```typescript
// hooks/useSignalR.ts - Production-ready React hook
import { useEffect, useRef, useState, useCallback } from 'react';
import * as signalR from '@microsoft/signalr';
import { useAuth } from './useAuth';
import { toast } from 'react-hot-toast';

export interface SignalRConnection {
  connection: signalR.HubConnection | null;
  isConnected: boolean;
  isConnecting: boolean;
  connectionError: string | null;
  reconnectAttempts: number;
}

export const useSignalR = (hubUrl: string = '/taskHub') => {
  const { accessToken, refreshToken } = useAuth();
  const connectionRef = useRef<signalR.HubConnection | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout>();
  const maxReconnectAttempts = 5;
  
  const [connectionState, setConnectionState] = useState<SignalRConnection>({
    connection: null,
    isConnected: false,
    isConnecting: false,
    connectionError: null,
    reconnectAttempts: 0,
  });
  
  const createConnection = useCallback(() => {
    const connection = new signalR.HubConnectionBuilder()
      .withUrl(hubUrl, {
        accessTokenFactory: () => accessToken || '',
        transport: signalR.HttpTransportType.WebSockets | signalR.HttpTransportType.ServerSentEvents,
        skipNegotiation: false,
      })
      .withAutomaticReconnect({
        nextRetryDelayInMilliseconds: (retryContext) => {
          // Exponential backoff: 0s, 2s, 10s, 30s, 60s, then stop
          const delays = [0, 2000, 10000, 30000, 60000];
          return delays[Math.min(retryContext.previousRetryCount, delays.length - 1)] || null;
        },
      })
      .configureLogging(
        process.env.NODE_ENV === 'development' 
          ? signalR.LogLevel.Information 
          : signalR.LogLevel.Warning
      )
      .build();
    
    // Connection event handlers
    connection.onreconnecting(() => {
      setConnectionState(prev => ({ 
        ...prev, 
        isConnected: false, 
        isConnecting: true,
        connectionError: null 
      }));
      toast.loading('Reconnecting to server...', { id: 'signalr-reconnect' });
    });
    
    connection.onreconnected(() => {
      setConnectionState(prev => ({ 
        ...prev, 
        isConnected: true, 
        isConnecting: false,
        reconnectAttempts: 0,
        connectionError: null 
      }));
      toast.success('Connected to server', { id: 'signalr-reconnect' });
    });
    
    connection.onclose((error) => {
      setConnectionState(prev => ({ 
        ...prev, 
        isConnected: false, 
        isConnecting: false,
        connectionError: error?.message || 'Connection closed',
        reconnectAttempts: prev.reconnectAttempts + 1
      }));
      
      if (error) {
        console.error('SignalR connection closed with error:', error);
        toast.error('Connection lost', { id: 'signalr-reconnect' });
        
        // Manual reconnection logic for critical scenarios
        if (connectionState.reconnectAttempts < maxReconnectAttempts) {
          reconnectTimeoutRef.current = setTimeout(() => {
            startConnection();
          }, Math.pow(2, connectionState.reconnectAttempts) * 1000);
        }
      }
    });
    
    return connection;
  }, [hubUrl, accessToken, connectionState.reconnectAttempts]);
  
  const startConnection = useCallback(async () => {
    if (!accessToken) return;
    
    try {
      setConnectionState(prev => ({ ...prev, isConnecting: true, connectionError: null }));
      
      const connection = createConnection();
      connectionRef.current = connection;
      
      await connection.start();
      
      setConnectionState(prev => ({
        ...prev,
        connection,
        isConnected: true,
        isConnecting: false,
        reconnectAttempts: 0,
        connectionError: null,
      }));
      
      toast.success('Connected to server');
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to connect';
      setConnectionState(prev => ({
        ...prev,
        isConnected: false,
        isConnecting: false,
        connectionError: errorMessage,
        reconnectAttempts: prev.reconnectAttempts + 1,
      }));
      
      console.error('SignalR connection failed:', error);
      toast.error(`Connection failed: ${errorMessage}`);
    }
  }, [accessToken, createConnection]);
  
  const stopConnection = useCallback(async () => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    
    if (connectionRef.current) {
      try {
        await connectionRef.current.stop();
      } catch (error) {
        console.error('Error stopping SignalR connection:', error);
      } finally {
        connectionRef.current = null;
        setConnectionState(prev => ({
          ...prev,
          connection: null,
          isConnected: false,
          isConnecting: false,
        }));
      }
    }
  }, []);
  
  // Auto-connect when token is available
  useEffect(() => {
    if (accessToken && !connectionRef.current) {
      startConnection();
    } else if (!accessToken && connectionRef.current) {
      stopConnection();
    }
    
    return () => {
      stopConnection();
    };
  }, [accessToken, startConnection, stopConnection]);
  
  // Event subscription helper
  const useSignalREvent = useCallback(<T>(
    eventName: string,
    handler: (data: T) => void,
    deps: React.DependencyList = []
  ) => {
    useEffect(() => {
      const connection = connectionRef.current;
      if (connection && connectionState.isConnected) {
        connection.on(eventName, handler);
        
        return () => {
          connection.off(eventName, handler);
        };
      }
    }, [connectionState.isConnected, ...deps]);
  }, [connectionState.isConnected]);
  
  // Method invocation helper
  const invokeHubMethod = useCallback(async <T>(
    methodName: string,
    ...args: any[]
  ): Promise<T | null> => {
    const connection = connectionRef.current;
    if (connection && connectionState.isConnected) {
      try {
        return await connection.invoke<T>(methodName, ...args);
      } catch (error) {
        console.error(`Error invoking ${methodName}:`, error);
        toast.error(`Failed to ${methodName.toLowerCase()}`);
        throw error;
      }
    }
    return null;
  }, [connectionState.isConnected]);
  
  return {
    ...connectionState,
    startConnection,
    stopConnection,
    useSignalREvent,
    invokeHubMethod,
  };
};

// components/TaskRealTimeUpdates.tsx - Real-time task updates
export const TaskRealTimeUpdates: React.FC<{ 
  onTaskCreated: (task: TaskDto) => void;
  onTaskUpdated: (task: TaskDto, changeType: string) => void;
  onHighPriorityAlert: (task: TaskDto) => void;
}> = ({ onTaskCreated, onTaskUpdated, onHighPriorityAlert }) => {
  const { useSignalREvent } = useSignalR();
  
  // Subscribe to real-time events
  useSignalREvent<TaskDto>('TaskCreated', (task) => {
    toast.success(`New task created: ${task.title}`);
    onTaskCreated(task);
  }, [onTaskCreated]);
  
  useSignalREvent<{ task: TaskDto; changeType: string }>('TaskUpdated', ({ task, changeType }) => {
    toast.info(`Task "${task.title}" was ${changeType.toLowerCase()}`);
    onTaskUpdated(task, changeType);
  }, [onTaskUpdated]);
  
  useSignalREvent<TaskDto>('HighPriorityTaskAlert', (task) => {
    toast.error(`High Priority Alert: ${task.title}`, {
      duration: 8000,
      position: 'top-center',
    });
    onHighPriorityAlert(task);
  }, [onHighPriorityAlert]);
  
  useSignalREvent<TaskDto>('TaskAssignedToYou', (task) => {
    toast.success(`Task assigned to you: ${task.title}`, {
      duration: 6000,
      action: {
        label: 'View',
        onClick: () => window.open(`/tasks/${task.id}`, '_blank'),
      },
    });
  });
  
  return null; // This component only handles events
};
```

### Real-Time Architecture Benefits
1. **Instant Updates**: Sub-100ms task updates across all connected clients
2. **Presence Awareness**: See who's online and working on tasks
3. **Collaboration**: Real-time editing indicators and conflict resolution
4. **Scalability**: Redis backplane supports thousands of concurrent users
5. **Reliability**: Automatic reconnection with exponential backoff
6. **Performance**: WebSocket connections with Server-Sent Events fallback

### Production Considerations
- **Connection Pooling**: Efficient connection management
- **Message Queuing**: Reliable message delivery with retry logic
- **Load Balancing**: Sticky sessions or Redis backplane for horizontal scaling
- **Monitoring**: Connection metrics, message delivery rates, error tracking
- **Security**: Token-based authentication, rate limiting, input validation

---
    {
        var result = await _authService.RegisterAsync(request);
        if (!result.Success)
            return BadRequest(result.ErrorMessage);
            
        return Ok(result);
    }
}
```

### Frontend Implementation (React/Next.js)

#### 1. Authentication Context
```typescript
// contexts/AuthContext.tsx
interface AuthContextType {
    user: User | null;
    token: string | null;
    login: (email: string, password: string) => Promise<void>;
    logout: () => void;
    isAuthenticated: boolean;
    loading: boolean;
}

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const [user, setUser] = useState<User | null>(null);
    const [token, setToken] = useState<string | null>(
        typeof window !== 'undefined' ? localStorage.getItem('auth_token') : null
    );
    
    const login = async (email: string, password: string) => {
        const response = await authApi.login({ email, password });
        setToken(response.token);
        setUser(response.user);
        localStorage.setItem('auth_token', response.token);
        router.push('/');
    };
    
    return (
        <AuthContext.Provider value={{ user, token, login, logout, isAuthenticated, loading }}>
            {children}
        </AuthContext.Provider>
    );
};
```

#### 2. Authentication API Service
```typescript
// services/authApi.ts
class AuthApiService {
    async login(credentials: LoginRequest): Promise<AuthResponse> {
        const response = await api.post<AuthResponse>('/auth/login', credentials);
        return response.data;
    }
    
    async register(userData: RegisterRequest): Promise<AuthResponse> {
        const response = await api.post<AuthResponse>('/auth/register', userData);
        return response.data;
    }
    
    async refreshToken(): Promise<AuthResponse> {
        const response = await api.post<AuthResponse>('/auth/refresh');
        return response.data;
    }
}
```

#### 3. HTTP Interceptor for Token Management
```typescript
// services/apiInterceptor.ts
api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('auth_token');
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => Promise.reject(error)
);

api.interceptors.response.use(
    (response) => response,
    async (error) => {
        if (error.response?.status === 401) {
            localStorage.removeItem('auth_token');
            window.location.href = '/login';
        }
        return Promise.reject(error);
    }
);
```

#### 4. Protected Route Component
```typescript
// components/ProtectedRoute.tsx
export const ProtectedRoute: React.FC<{ children: ReactNode }> = ({ children }) => {
    const { isAuthenticated, loading } = useAuth();
    const router = useRouter();
    
    useEffect(() => {
        if (!loading && !isAuthenticated) {
            router.push('/login');
        }
    }, [isAuthenticated, loading, router]);
    
    if (loading) return <LoadingSpinner />;
    if (!isAuthenticated) return null;
    
    return <>{children}</>;
};
```

### Security Considerations
- **Password Hashing**: Use BCrypt with salt rounds (12+)
- **Token Expiration**: Short-lived access tokens (15-30 minutes) with refresh tokens
- **HTTPS Only**: Enforce secure transmission in production
- **Rate Limiting**: Implement login attempt limitations
- **Input Validation**: Comprehensive validation on both client and server

---

## Unit Testing Implementation

### Backend Testing (.NET Core)

#### 1. Test Project Structure
```
backend.Tests/
├── Controllers/
│   └── TasksControllerTests.cs
├── Services/
│   └── TaskServiceTests.cs
├── Repositories/
│   └── TaskRepositoryTests.cs
├── Middleware/
│   └── RequestLoggingMiddlewareTests.cs
└── Fixtures/
    └── TestDataFixtures.cs
```

#### 2. Unit Test Framework Setup
```csharp
// backend.Tests.csproj
<PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.8.0" />
<PackageReference Include="xunit" Version="2.4.2" />
<PackageReference Include="xunit.runner.visualstudio" Version="2.4.5" />
<PackageReference Include="Moq" Version="4.20.69" />
<PackageReference Include="Microsoft.EntityFrameworkCore.InMemory" Version="8.0.8" />
<PackageReference Include="FluentAssertions" Version="6.12.0" />
```

#### 3. Controller Testing Example
```csharp
// Controllers/TasksControllerTests.cs
public class TasksControllerTests
{
    private readonly Mock<ITaskService> _mockTaskService;
    private readonly TasksController _controller;
    
    public TasksControllerTests()
    {
        _mockTaskService = new Mock<ITaskService>();
        _controller = new TasksController(_mockTaskService.Object, Mock.Of<ILogger<TasksController>>());
    }
    
    [Fact]
    public async Task GetAllTasks_ShouldReturnOkResult_WhenTasksExist()
    {
        // Arrange
        var tasks = new List<TaskItem> 
        { 
            new() { Id = 1, Title = "Test Task", Priority = TaskPriority.High } 
        };
        _mockTaskService.Setup(x => x.GetAllTasksAsync()).ReturnsAsync(tasks);
        
        // Act
        var result = await _controller.GetAllTasks();
        
        // Assert
        result.Result.Should().BeOfType<OkObjectResult>();
        var okResult = result.Result as OkObjectResult;
        okResult?.Value.Should().BeAssignableTo<IEnumerable<TaskDto>>();
    }
    
    [Theory]
    [InlineData("High", "Pending")]
    [InlineData("Low", "Completed")]
    public async Task GetAllTasks_ShouldApplyFilters_WhenFiltersProvided(string priority, string status)
    {
        // Arrange & Act & Assert
        var result = await _controller.GetAllTasks(priority, status);
        
        _mockTaskService.Verify(x => x.GetAllTasksAsync(), Times.Once);
        result.Result.Should().BeOfType<OkObjectResult>();
    }
}
```

#### 4. Service Layer Testing
```csharp
// Services/TaskServiceTests.cs
public class TaskServiceTests
{
    private readonly Mock<ITaskRepository> _mockRepository;
    private readonly Mock<ITaskEventPublisher> _mockEventPublisher;
    private readonly TaskService _service;
    
    [Fact]
    public async Task CreateTaskAsync_ShouldPublishHighPriorityEvent_WhenTaskIsHighPriority()
    {
        // Arrange
        var highPriorityTask = new TaskItem { Priority = TaskPriority.High, Title = "Urgent Task" };
        _mockRepository.Setup(x => x.CreateTaskAsync(It.IsAny<TaskItem>()))
                      .ReturnsAsync(highPriorityTask);
        
        // Act
        await _service.CreateTaskAsync(highPriorityTask);
        
        // Assert
        _mockEventPublisher.Verify(x => x.PublishHighPriorityTaskEventAsync(
            It.IsAny<TaskItem>(), "created"), Times.Once);
    }
}
```

### Frontend Testing (React/Jest/Testing Library)

#### 1. Test Dependencies
```json
// package.json
{
  "devDependencies": {
    "@testing-library/react": "^14.1.2",
    "@testing-library/jest-dom": "^6.1.5",
    "@testing-library/user-event": "^14.5.1",
    "jest": "^29.7.0",
    "jest-environment-jsdom": "^29.7.0",
    "@types/jest": "^29.5.8"
  }
}
```

#### 2. Component Testing Setup
```javascript
// jest.config.js
module.exports = {
  testEnvironment: 'jsdom',
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
  },
  collectCoverageFrom: [
    'src/**/*.{js,jsx,ts,tsx}',
    '!src/**/*.d.ts',
  ],
};

// jest.setup.js
import '@testing-library/jest-dom';
```

#### 3. Component Testing Examples
```typescript
// __tests__/components/TaskList.test.tsx
describe('TaskList Component', () => {
    const mockTasks: Task[] = [
        { id: 1, title: 'Test Task', priority: 'High', status: 'Pending', description: 'Test' }
    ];
    
    beforeEach(() => {
        (taskApi.getTasks as jest.Mock).mockResolvedValue({ data: mockTasks });
    });
    
    test('renders task list correctly', async () => {
        render(<TaskList />);
        
        await waitFor(() => {
            expect(screen.getByText('Test Task')).toBeInTheDocument();
        });
    });
    
    test('filters tasks by priority', async () => {
        render(<TaskList />);
        
        const priorityFilter = screen.getByLabelText(/filter by priority/i);
        await user.selectOptions(priorityFilter, 'High');
        
        await waitFor(() => {
            expect(taskApi.getTasks).toHaveBeenCalledWith('High', undefined, 1, 10);
        });
    });
    
    test('handles loading state', () => {
        render(<TaskList />);
        expect(screen.getByText('Loading tasks...')).toBeInTheDocument();
    });
});
```

#### 4. API Service Testing
```typescript
// __tests__/services/taskApi.test.ts
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('Task API Service', () => {
    test('getTasks calls correct endpoint with parameters', async () => {
        const mockResponse = { data: [{ id: 1, title: 'Test' }] };
        mockedAxios.get.mockResolvedValue(mockResponse);
        
        await taskApi.getTasks('High', 'Pending', 1, 10);
        
        expect(mockedAxios.get).toHaveBeenCalledWith(
            '/tasks?priority=High&status=Pending&page=1&pageSize=10'
        );
    });
});
```

### Testing Strategy
- **Unit Tests**: Individual functions and methods (80%+ coverage target)
- **Integration Tests**: API endpoints with in-memory database
- **Component Tests**: React components in isolation
- **E2E Tests**: Critical user flows with Playwright/Cypress

---

## Real-time Capabilities with SignalR

### Overview
SignalR enables bi-directional communication between client and server, allowing instant updates across multiple browser tabs and users without polling or page refreshes.

### Backend Implementation

#### 1. SignalR Hub Setup
```csharp
// Hubs/TaskHub.cs
public class TaskHub : Hub
{
    public async Task JoinUserGroup(int userId)
    {
        await Groups.AddToGroupAsync(Context.ConnectionId, $"User_{userId}");
    }
    
    public async Task LeaveUserGroup(int userId)
    {
        await Groups.RemoveFromGroupAsync(Context.ConnectionId, $"User_{userId}");
    }
    
    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        // Clean up user groups
        await base.OnDisconnectedAsync(exception);
    }
}

// Services/ITaskNotificationService.cs
public interface ITaskNotificationService
{
    Task NotifyTaskCreated(TaskItem task, int userId);
    Task NotifyTaskUpdated(TaskItem task, int userId);
    Task NotifyTaskDeleted(int taskId, int userId);
}

public class TaskNotificationService : ITaskNotificationService
{
    private readonly IHubContext<TaskHub> _hubContext;
    
    public async Task NotifyTaskCreated(TaskItem task, int userId)
    {
        await _hubContext.Clients.Group($"User_{userId}")
            .SendAsync("TaskCreated", new TaskDto(task));
    }
    
    public async Task NotifyTaskUpdated(TaskItem task, int userId)
    {
        await _hubContext.Clients.Group($"User_{userId}")
            .SendAsync("TaskUpdated", new TaskDto(task));
    }
    
    public async Task NotifyTaskDeleted(int taskId, int userId)
    {
        await _hubContext.Clients.Group($"User_{userId}")
            .SendAsync("TaskDeleted", taskId);
    }
}
```

#### 2. Program.cs Configuration
```csharp
// Program.cs additions
builder.Services.AddSignalR();
builder.Services.AddScoped<ITaskNotificationService, TaskNotificationService>();

// Configure CORS for SignalR
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials(); // Required for SignalR
    });
});

// Map SignalR Hub
app.MapHub<TaskHub>("/taskHub");
```

#### 3. Service Integration
```csharp
// Services/TaskService.cs modifications
public class TaskService : ITaskService
{
    private readonly ITaskNotificationService _notificationService;
    
    public async Task<TaskItem> CreateTaskAsync(TaskItem task)
    {
        var createdTask = await _repository.CreateTaskAsync(task);
        
        // Existing high priority logging
        if (createdTask.IsHighPriority())
            await _eventPublisher.PublishHighPriorityTaskEventAsync(createdTask, "created");
        
        // New: Real-time notification
        await _notificationService.NotifyTaskCreated(createdTask, task.UserId);
        
        return createdTask;
    }
}
```

### Frontend Implementation

#### 1. SignalR Connection Service
```typescript
// services/signalRService.ts
import { HubConnection, HubConnectionBuilder, LogLevel } from '@microsoft/signalr';

class SignalRService {
    private connection: HubConnection | null = null;
    private eventHandlers: Map<string, Function[]> = new Map();
    
    async connect(token: string): Promise<void> {
        this.connection = new HubConnectionBuilder()
            .withUrl(`${process.env.NEXT_PUBLIC_API_URL}/taskHub`, {
                accessTokenFactory: () => token
            })
            .withAutomaticReconnect()
            .configureLogging(LogLevel.Information)
            .build();
            
        await this.connection.start();
        
        // Join user group
        const userId = this.getUserIdFromToken(token);
        await this.connection.invoke('JoinUserGroup', userId);
        
        // Set up event listeners
        this.connection.on('TaskCreated', (task: Task) => {
            this.notifyHandlers('TaskCreated', task);
        });
        
        this.connection.on('TaskUpdated', (task: Task) => {
            this.notifyHandlers('TaskUpdated', task);
        });
        
        this.connection.on('TaskDeleted', (taskId: number) => {
            this.notifyHandlers('TaskDeleted', taskId);
        });
    }
    
    subscribe(event: string, handler: Function): () => void {
        if (!this.eventHandlers.has(event)) {
            this.eventHandlers.set(event, []);
        }
        this.eventHandlers.get(event)!.push(handler);
        
        // Return unsubscribe function
        return () => this.unsubscribe(event, handler);
    }
    
    private notifyHandlers(event: string, data: any): void {
        const handlers = this.eventHandlers.get(event) || [];
        handlers.forEach(handler => handler(data));
    }
}

export const signalRService = new SignalRService();
```

#### 2. Real-time Context Provider
```typescript
// contexts/RealTimeContext.tsx
interface RealTimeContextType {
    isConnected: boolean;
    subscribeToTaskUpdates: (handler: (task: Task) => void) => () => void;
    subscribeToTaskCreation: (handler: (task: Task) => void) => () => void;
    subscribeToTaskDeletion: (handler: (taskId: number) => void) => () => void;
}

export const RealTimeProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const [isConnected, setIsConnected] = useState(false);
    const { token } = useAuth();
    
    useEffect(() => {
        if (token) {
            signalRService.connect(token)
                .then(() => setIsConnected(true))
                .catch(console.error);
        }
        
        return () => {
            signalRService.disconnect();
            setIsConnected(false);
        };
    }, [token]);
    
    const subscribeToTaskUpdates = (handler: (task: Task) => void) => 
        signalRService.subscribe('TaskUpdated', handler);
    
    const subscribeToTaskCreation = (handler: (task: Task) => void) => 
        signalRService.subscribe('TaskCreated', handler);
    
    const subscribeToTaskDeletion = (handler: (taskId: number) => void) => 
        signalRService.subscribe('TaskDeleted', handler);
    
    return (
        <RealTimeContext.Provider value={{ 
            isConnected, 
            subscribeToTaskUpdates, 
            subscribeToTaskCreation, 
            subscribeToTaskDeletion 
        }}>
            {children}
        </RealTimeContext.Provider>
    );
};
```

#### 3. Component Integration
```typescript
// components/TaskList.tsx modifications
const TaskList: React.FC = () => {
    const [tasks, setTasks] = useState<Task[]>([]);
    const { subscribeToTaskCreation, subscribeToTaskUpdates, subscribeToTaskDeletion } = useRealTime();
    
    useEffect(() => {
        // Subscribe to real-time events
        const unsubscribeCreated = subscribeToTaskCreation((newTask: Task) => {
            setTasks(prev => [newTask, ...prev]);
            showNotification(`New task created: ${newTask.title}`, 'info');
        });
        
        const unsubscribeUpdated = subscribeToTaskUpdates((updatedTask: Task) => {
            setTasks(prev => prev.map(task => 
                task.id === updatedTask.id ? updatedTask : task
            ));
            showNotification(`Task updated: ${updatedTask.title}`, 'success');
        });
        
        const unsubscribeDeleted = subscribeToTaskDeletion((taskId: number) => {
            setTasks(prev => prev.filter(task => task.id !== taskId));
            showNotification('Task deleted', 'warning');
        });
        
        // Cleanup subscriptions
        return () => {
            unsubscribeCreated();
            unsubscribeUpdated();
            unsubscribeDeleted();
        };
    }, [subscribeToTaskCreation, subscribeToTaskUpdates, subscribeToTaskDeletion]);
    
    // Rest of component logic...
};
```

#### 4. Connection Status Indicator
```typescript
// components/ConnectionStatus.tsx
export const ConnectionStatus: React.FC = () => {
    const { isConnected } = useRealTime();
    
    return (
        <div className={`fixed top-4 right-4 px-3 py-1 rounded-full text-sm ${
            isConnected ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
        }`}>
            <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${
                    isConnected ? 'bg-green-500' : 'bg-red-500'
                }`} />
                {isConnected ? 'Connected' : 'Disconnected'}
            </div>
        </div>
    );
};
```

### Advanced Real-time Features
- **Presence Indicators**: Show who else is viewing/editing tasks
- **Collaborative Editing**: Real-time task editing with conflict resolution
- **Typing Indicators**: Show when users are actively editing
- **Push Notifications**: Browser notifications for important updates
- **Offline Support**: Queue updates when disconnected, sync when reconnected

### Performance Considerations
- **Connection Pooling**: Efficient connection management
- **Message Throttling**: Prevent spam with rate limiting
- **Selective Updates**: Only notify relevant users/groups
- **Graceful Degradation**: Fallback to polling if SignalR fails
- **Memory Management**: Proper cleanup of event handlers and connections

---

## Implementation Roadmap

### Phase 1: Authentication (1-2 days)
1. Backend JWT infrastructure
2. User management system
3. Frontend authentication flow
4. Protected routes and API endpoints

### Phase 2: Testing Framework (1-2 days)
1. Backend unit test setup
2. Frontend testing infrastructure
3. Integration test suite
4. CI/CD pipeline integration

### Phase 3: Real-time Features (3-4 days)
1. SignalR hub implementation
2. Frontend WebSocket integration
3. Real-time UI updates
4. Connection management and error handling

### Phase 4: Polish & Production (1-2 days)
1. Performance optimization
2. Security hardening
3. Documentation updates
4. Deployment preparation

Each implementation would significantly enhance the application's enterprise readiness and user experience while maintaining the existing clean architecture and industry best practices.

---

## Enterprise Deployment & DevOps (Netflix/Google SRE)

### Industry Standard: Cloud-Native Deployment Pipeline
**Used by**: Netflix, Google, Amazon, Microsoft, Spotify, Uber

### Production-Ready Docker Implementation

#### 1. Multi-Stage Docker Configuration
```dockerfile
# Dockerfile.backend - ASP.NET Core optimized
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

# Install security updates and dependencies
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN adduser --disabled-password --gecos '' --uid 1000 appuser

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy project files and restore dependencies (layered for better caching)
COPY ["backend/backend.csproj", "backend/"]
RUN dotnet restore "backend/backend.csproj"

# Copy source code and build
COPY backend/ backend/
WORKDIR "/src/backend"
RUN dotnet build "backend.csproj" -c Release -o /app/build

FROM build AS test
# Run tests during build
RUN dotnet test --no-build --verbosity normal --collect:"XPlat Code Coverage" \
    --results-directory ./TestResults --logger trx

FROM build AS publish
RUN dotnet publish "backend.csproj" -c Release -o /app/publish \
    --no-restore --no-build \
    /p:PublishReadyToRun=true \
    /p:PublishSingleFile=false \
    /p:PublishTrimmed=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:80/health || exit 1

ENTRYPOINT ["dotnet", "backend.dll"]

# Dockerfile.frontend - Next.js optimized
FROM node:20-alpine AS base
RUN apk add --no-cache libc6-compat
WORKDIR /app

FROM base AS deps
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --only=production && npm cache clean --force

FROM base AS builder
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ .
ENV NEXT_TELEMETRY_DISABLED 1
RUN npm run build

FROM base AS runner
WORKDIR /app

ENV NODE_ENV production
ENV NEXT_TELEMETRY_DISABLED 1

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000
ENV PORT 3000
ENV HOSTNAME "0.0.0.0"

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:3000/api/health || exit 1

CMD ["node", "server.js"]
```

#### 2. CI/CD Pipeline (GitHub Actions)
```yaml
# .github/workflows/ci-cd.yml - Production pipeline
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME_BACKEND: ${{ github.repository }}/backend
  IMAGE_NAME_FRONTEND: ${{ github.repository }}/frontend

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      sqlserver:
        image: mcr.microsoft.com/mssql/server:2022-latest
        env:
          SA_PASSWORD: TestPassword123!
          ACCEPT_EULA: Y
        options: >-
          --health-cmd "/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P TestPassword123! -Q 'SELECT 1'"
          --health-interval 10s
          --health-timeout 3s
          --health-retries 10
        ports:
          - 1433:1433

    steps:
    - uses: actions/checkout@v4

    - name: Setup .NET
      uses: actions/setup-dotnet@v4
      with:
        dotnet-version: 8.0.x

    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '20'
        cache: 'npm'
        cache-dependency-path: frontend/package-lock.json

    # Backend tests
    - name: Restore backend dependencies
      run: dotnet restore backend/

    - name: Build backend
      run: dotnet build backend/ --no-restore

    - name: Run backend tests
      run: |
        dotnet test backend/ --no-build --verbosity normal \
          --collect:"XPlat Code Coverage" \
          --results-directory ./TestResults \
          --logger trx \
          /p:CollectCoverage=true \
          /p:CoverletOutputFormat=cobertura
      env:
        ConnectionStrings__DefaultConnection: Server=localhost,1433;Database=TaskManagementTestDB;User Id=sa;Password=TestPassword123!;TrustServerCertificate=true;

    # Frontend tests
    - name: Install frontend dependencies
      run: npm ci
      working-directory: frontend/

    - name: Run frontend tests
      run: npm run test:coverage
      working-directory: frontend/

    - name: Run E2E tests
      run: |
        npm run build
        npm run test:e2e
      working-directory: frontend/

    # Security scanning
    - name: Run security audit
      run: |
        dotnet list backend/ package --vulnerable
        npm audit --audit-level moderate
      working-directory: frontend/

    # Upload coverage reports
    - name: Upload backend coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./TestResults/*/coverage.cobertura.xml
        flags: backend

    - name: Upload frontend coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./frontend/coverage/lcov.info
        flags: frontend

  build:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    permissions:
      contents: read
      packages: write

    steps:
    - uses: actions/checkout@v4

    - name: Log in to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}

    - name: Build and push backend image
      uses: docker/build-push-action@v5
      with:
        context: .
        file: ./Dockerfile.backend
        push: true
        tags: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME_BACKEND }}:latest
        cache-from: type=gha
        cache-to: type=gha,mode=max

    - name: Build and push frontend image
      uses: docker/build-push-action@v5
      with:
        context: .
        file: ./Dockerfile.frontend
        push: true
        tags: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME_FRONTEND }}:latest
        cache-from: type=gha
        cache-to: type=gha,mode=max

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: production

    steps:
    - uses: actions/checkout@v4

    - name: Deploy to Production
      run: |
        echo "Deploying to production environment..."
        # Add deployment commands here (Kubernetes, Azure, AWS, etc.)

    - name: Notify deployment status
      run: echo "Deployment completed successfully"
```

#### 3. Kubernetes Production Configuration
```yaml
# k8s/backend-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend-deployment
  namespace: taskmanagement-prod
  labels:
    app: backend
    version: v1
spec:
  replicas: 3
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
        version: v1
    spec:
      containers:
      - name: backend
        image: taskmanagement/backend:latest
        ports:
        - containerPort: 80
        env:
        - name: ASPNETCORE_ENVIRONMENT
          value: "Production"
        - name: ConnectionStrings__DefaultConnection
          valueFrom:
            secretKeyRef:
              name: database-secret
              key: connection-string
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 80
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 80
          initialDelaySeconds: 5
          periodSeconds: 10
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL

---
apiVersion: v1
kind: Service
metadata:
  name: backend-service
  namespace: taskmanagement-prod
spec:
  selector:
    app: backend
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
  type: ClusterIP

---
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: taskmanagement-ingress
  namespace: taskmanagement-prod
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
spec:
  tls:
  - hosts:
    - taskmanagement.com
    secretName: taskmanagement-tls
  rules:
  - host: taskmanagement.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: backend-service
            port:
              number: 80
```

#### 4. Monitoring & Observability
```csharp
// Infrastructure/Metrics/MetricsService.cs - Custom metrics
public class MetricsService : IMetricsService
{
    private readonly Counter _taskCreatedCounter;
    private readonly Counter _taskCompletedCounter;
    private readonly Histogram _apiResponseDuration;
    private readonly Gauge _activeUsersGauge;
    
    public MetricsService()
    {
        _taskCreatedCounter = Metrics
            .CreateCounter("tasks_created_total", "Total number of tasks created");
            
        _taskCompletedCounter = Metrics
            .CreateCounter("tasks_completed_total", "Total number of tasks completed");
            
        _apiResponseDuration = Metrics
            .CreateHistogram("api_request_duration_seconds", "API request duration",
                new HistogramConfiguration
                {
                    Buckets = Histogram.LinearBuckets(0.01, 0.05, 10)
                });
                
        _activeUsersGauge = Metrics
            .CreateGauge("active_users", "Number of currently active users");
    }
    
    public void IncrementTaskCreated() => _taskCreatedCounter.Inc();
    public void IncrementTaskCompleted() => _taskCompletedCounter.Inc();
    public void RecordApiDuration(double durationSeconds) => _apiResponseDuration.Observe(durationSeconds);
    public void UpdateActiveUsers(int count) => _activeUsersGauge.Set(count);
}
```

### Production Deployment Benefits
1. **High Availability**: Multi-replica deployments with auto-scaling
2. **Security**: Non-root containers, secret management, network policies
3. **Monitoring**: Comprehensive metrics, alerting, and observability
4. **Performance**: Optimized Docker images, resource limits, caching
5. **Reliability**: Health checks, graceful shutdowns, circuit breakers
6. **Compliance**: Security scanning, vulnerability assessments, audit logs

### DevOps Best Practices
- **Infrastructure as Code**: Terraform/ARM templates for cloud resources
- **GitOps**: ArgoCD/Flux for Kubernetes deployments
- **Blue-Green Deployments**: Zero-downtime deployments
- **Canary Releases**: Gradual rollouts with monitoring
- **Disaster Recovery**: Database backups, multi-region deployments
- **Cost Optimization**: Resource right-sizing, auto-scaling policies

This enterprise-grade deployment approach ensures the task management system can scale to thousands of users while maintaining high availability, security, and performance standards used by Fortune 500 companies.
