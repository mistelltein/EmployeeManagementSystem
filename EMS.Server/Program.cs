using EMS.ServerLibrary.Data;
using EMS.ServerLibrary.Helpers;
using EMS.ServerLibrary.Repositories.Contracts;
using EMS.ServerLibrary.Repositories.Implementations;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("EmployeeManagementSystem") ?? 
        throw new InvalidOperationException("Sorry, your connection is not found"));
});

builder.Services.Configure<JwtSection>(builder.Configuration.GetSection("JwtSection"));
builder.Services.AddScoped<IUserAccount, UserAccountRepository>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
