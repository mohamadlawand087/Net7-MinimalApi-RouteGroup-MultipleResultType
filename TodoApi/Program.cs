using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using TodoApi.Filters;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration["ConnectionStrings:DefaultConnection"];
builder.Services.AddDbContext<ApiDbContext>(options =>
    options.UseSqlite(connectionString));

var securityScheme = new OpenApiSecurityScheme()
{
    Name = "Authorization",
    Type = SecuritySchemeType.ApiKey,
    Scheme = "Bearer",
    BearerFormat = "JWT",
    In = ParameterLocation.Header,
    Description = "JSON Web Token based security",
};

var securityReq = new OpenApiSecurityRequirement()
{
    {
        new OpenApiSecurityScheme
        {
            Reference = new OpenApiReference
            {
                Type = ReferenceType.SecurityScheme,
                Id = "Bearer"
            }
        },
        new string[] {}
    }
};

var contactInfo = new OpenApiContact()
{
    Name = "Mohamad Lawand",
    Email = "hello@mohamadlawand.com",
    Url = new Uri("https://mohamadlawand.com") 
};

var license = new OpenApiLicense()
{
    Name = "Free License",
};

var info = new OpenApiInfo()
{
    Version = "V1",
    Title = "Todo List Api with JWT Authentication",
    Description = "Todo List Api with JWT Authentication",
    Contact = contactInfo,
    License = license
};

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options => {
    options.SwaggerDoc("v1", info);
    options.AddSecurityDefinition("Bearer", securityScheme);
    options.AddSecurityRequirement(securityReq);
});

builder.Services.AddAuthentication(options => {
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer (options => {
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        ValidateAudience = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
        ValidateLifetime = false, // In any other application other then demo this needs to be true,
        ValidateIssuerSigningKey = true
    };
});

builder.Services.AddAuthentication();
builder.Services.AddAuthorization();

var app = builder.Build();

app.MapGet("/items", [Authorize] async (ApiDbContext db) =>
{
    return await db.Items.ToListAsync();
});

app.MapPost("/items", [Authorize] async (ApiDbContext db, Item item) =>
{
    if (await db.Items.FirstOrDefaultAsync(x => x.Id == item.Id) != null)
    {
        return Results.BadRequest();
    }

    db.Items.Add(item);
    await db.SaveChangesAsync();
    return Results.Created($"/Items/{item.Id}", item);
}).AddFilter<ValidationFilter<Item>>();

int? ParamCheck(RouteHandlerInvocationContext context) 
{

    if(context.Parameters.SingleOrDefault() != null)
    {
        int nb;
        var param =  context.Parameters.Single();
        var result = int.TryParse(param?.ToString(), out nb);
        return nb;
    }
    
    return null;
}

app.MapGet("/items/{id}", [Authorize] async (ApiDbContext db, int id) =>
{
    var item = await db.Items.FirstOrDefaultAsync(x => x.Id == id);

    return item == null ? Results.NotFound() : Results.Ok(item);
}).AddFilter((ctx, next) => async (context) =>
{
    return  ParamCheck(context)  != null ? Results.BadRequest("Invalid parameters") : await next(context);
});

app.MapPut("/items/{id}", [Authorize] async (ApiDbContext db, int id, Item item) =>
{
    var existItem = await db.Items.FirstOrDefaultAsync(x => x.Id == id);
    if(existItem == null)
    {
        return Results.BadRequest();
    }

    existItem.Title = item.Title;
    existItem.IsCompleted = item.IsCompleted;

    await db.SaveChangesAsync();
    return Results.Ok(item);
});

app.MapDelete("/items/{id}", [Authorize] async (ApiDbContext db, int id) => 
{
    var existItem = await db.Items.FirstOrDefaultAsync(x => x.Id == id);
    if(existItem == null)
    {
        return Results.BadRequest();
    }

    db.Items.Remove(existItem);
    await db.SaveChangesAsync();
    return Results.NoContent();
});

app.MapPost("/accounts/login", [AllowAnonymous] (UserDto user) => {
    if(user.username == "admin@mohamadlawand.com" && user.password == "Password123")
    {
        var secureKey = Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]);

        var issuer = builder.Configuration["Jwt:Issuer"];
        var audience = builder.Configuration["Jwt:Audience"];
        var securityKey = new SymmetricSecurityKey(secureKey);
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512);

        var jwtTokenHandler = new JwtSecurityTokenHandler();

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new [] {
                new Claim("Id", "1"),
                new Claim(JwtRegisteredClaimNames.Sub, user.username),
                new Claim(JwtRegisteredClaimNames.Email, user.username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            }),
            Expires = DateTime.Now.AddMinutes(5),
            Audience = audience,
            Issuer = issuer,
            SigningCredentials = credentials
        };

        var token = jwtTokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = jwtTokenHandler.WriteToken(token);
        return Results.Ok(jwtToken);  
    }
    return Results.Unauthorized();
});

app.UseSwagger();
app.UseSwaggerUI();

app.MapGroup("/v1").RequireAuthorization().MapCrudTodoApi();
app.MapGroup("/v1").MapAuthenticationForApi();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Hello from Minimal API");
app.Run();

// record Item(int id, string title, bool IsCompleted);

record UserDto (string username, string password);

class Item
{
    public int Id { get; set; }
    public string Title { get; set; }
    public bool IsCompleted { get; set; }
}

class ApiDbContext : DbContext
{
    public DbSet<Item> Items { get; set; }

    public ApiDbContext(DbContextOptions<ApiDbContext> options) : base(options)
    {
    }
}

// Creating a new class so we can group the endpoint
static class TodoApiV1
{
    // Static method which will attach to the middleware to add the endpoints
    public static IEndpointRouteBuilder MapCrudTodoApi(this IEndpointRouteBuilder routes)
    {
        // Start adding the endpoints
        routes.MapGet("/items", GetAllItems);
        routes.MapGet("/items/{id}", GetItem);
        routes.MapPost("/items", CreateItem).AddFilter<ValidationFilter<Item>>();
        routes.MapPut("/items/{id}", UpdateItem).AddFilter<ValidationFilter<Item>>();
        routes.MapDelete("/items/{id}", DeleteItem);
        return routes;
    }

    // Get all method
    public static async Task<Ok<List<Item>>> GetAllItems(ApiDbContext db)
    {
        return TypedResults.Ok(await db.Items.ToListAsync());
    }

    public static async Task<Results<Ok<Item>, NotFound>> GetItem(ApiDbContext db, int id)
    {
        return await db.Items.FirstOrDefaultAsync(x => x.Id == id) is Item item
        ? TypedResults.Ok(item)
        : TypedResults.NotFound();
    }

    public static async Task<Results<Created<Item>, BadRequest>> CreateItem(ApiDbContext db, Item item)
    {
        if (await db.Items.FirstOrDefaultAsync(x => x.Id == item.Id) != null)
        {
            return TypedResults.BadRequest();
        }

        db.Items.Add(item);
        await db.SaveChangesAsync();
        return TypedResults.Created($"/v1/items/{item.Id}", item);
    }

    public static async Task<Results<NoContent, NotFound>> UpdateItem(ApiDbContext db, Item item, int id)
    {
        var existItem = await db.Items.FirstOrDefaultAsync(x => x.Id == id);
        if(existItem == null)
        {
            return TypedResults.NotFound();
        }

        existItem.Title = item.Title;
        existItem.IsCompleted = item.IsCompleted;

        await db.SaveChangesAsync();
        return TypedResults.NoContent();
    }

    public static async Task<Results<NoContent, NotFound>> DeleteItem(ApiDbContext db, int id)
    {
        var existItem = await db.Items.FirstOrDefaultAsync(x => x.Id == id);
        if(existItem == null)
        {
        return TypedResults.NotFound();
        }

        db.Items.Remove(existItem);
        await db.SaveChangesAsync();
        return TypedResults.NoContent();
    }
}

static class TodoAuthentication
{
    public static IEndpointRouteBuilder MapAuthenticationForApi(this IEndpointRouteBuilder routes)
    {
        routes.MapPost("/accounts/login", Login);
        return routes;
    }

    public static async Task<Results<Ok<string>, UnauthorizedHttpResult>> Login(UserDto user, IConfiguration config)
    {
        if(user.username == "admin@mohamadlawand.com" && user.password == "Password123")
        {
            var secureKey = Encoding.UTF8.GetBytes(config["Jwt:Key"]);

            var issuer = config["Jwt:Issuer"];
            var audience = config["Jwt:Audience"];
            var securityKey = new SymmetricSecurityKey(secureKey);
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512);

            var jwtTokenHandler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new [] {
                    new Claim("Id", "1"),
                    new Claim(JwtRegisteredClaimNames.Sub, user.username),
                    new Claim(JwtRegisteredClaimNames.Email, user.username),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                Expires = DateTime.Now.AddMinutes(5),
                Audience = audience,
                Issuer = issuer,
                SigningCredentials = credentials
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);
            return TypedResults.Ok(jwtToken);  
        }
        return TypedResults.Unauthorized();
    }
}