using AuthenticationCenter.Configuration;
using AuthenticationCenter.Helpers;
using AuthenticationCenter.Interfaces;
using AuthenticationCenter.Repository;
using AuthenticationCenter.Services;
using AuthenticationCenter.Configuration;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.Configure<SmtpSetting>(builder.Configuration.GetSection("SmtpSettings"));
builder.Services.Configure<JwtSetting>(builder.Configuration.GetSection("JwtSetting"));
builder.Services.Configure<Database>(builder.Configuration.GetSection("Database"));
builder.Services.AddScoped<DapperManager>();
builder.Services.AddSingleton<GenerateToken>();
builder.Services.AddSingleton<SecurityUsers>();
builder.Services.AddTransient<EmailService>();
builder.Services.AddScoped<IRegisterRepository, RegisterRepository>();
builder.Services.AddScoped<ILoginRepository, LoginRepository>();
builder.Services.AddScoped<IRefreshToken, RefreshToken>();
builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();