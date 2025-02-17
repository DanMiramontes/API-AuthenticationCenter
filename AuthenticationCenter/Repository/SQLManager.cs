using System.Data;
using System.Data.SqlClient;
using AuthenticationCenter.Configuration;
using Dapper;
using Microsoft.Extensions.Options;

namespace AuthenticationCenter.Repository;

public class DapperManager : IAsyncDisposable
{
    private readonly SqlConnection _connection;
    private SqlTransaction _transaction;
    string connectionString;

    private readonly Database _database;
    
    public DapperManager(IOptions<Database> database)
    {
        _database = database.Value;
        connectionString = _database.ConexionString.ToString();
        _connection = new SqlConnection(connectionString);
    }
    
    
    public async Task OpenConnectionAsync()
    {
        if (_connection.State == ConnectionState.Closed)
            await _connection.OpenAsync();
    }
    
    public async Task CloseConnectionAsync()
    {
        if (_connection.State != ConnectionState.Closed)
            await _connection.CloseAsync();  // Usamos CloseAsync()
    }
    
    public async Task BeginTransactionAsync()
    {
        if (_connection.State == ConnectionState.Closed)
            throw new InvalidOperationException("La conexión debe estar abierta para iniciar una transacción.");
        
        _transaction = await Task.Run(() => _connection.BeginTransaction());
    }
    
    public async Task CommitAsync()
    {
        if (_transaction == null)
            throw new InvalidOperationException("No hay una transacción activa para realizar Commit.");
        
        await Task.Run(() => _transaction.Commit());
        _transaction = null;
    }
    
    public async Task RollbackAsync()
    {
        if (_transaction == null)
            throw new InvalidOperationException("No hay una transacción activa para realizar Rollback.");
       
        await Task.Run(() => _transaction.Rollback());
        _transaction = null;
    }
    
    public async Task<int> Execute(string query, object parameters = null)
    {
        return  await _connection.ExecuteAsync(query, parameters, _transaction);
    }
    
    // Ejecuta un comando SELECT y devuelve una lista de objetos
    public async Task<IEnumerable<T>> QueryAsync<T>(string query, object parameters = null)
    {
        return await _connection.QueryAsync<T>(query, parameters, _transaction);
    }
    
    // Ejecuta un comando SELECT y devuelve un solo objeto
    public async Task<T> QuerySingleAsync<T>(string query, object parameters = null)
    {
        return await _connection.QuerySingleOrDefaultAsync<T>(query, parameters, _transaction);
    }
    
    public async Task<T> ExecuteScalarAsync<T>(string query, object parameters = null)
    {
        return await _connection.ExecuteScalarAsync<T>(query, parameters, _transaction);
    }
    
    public async ValueTask DisposeAsync()
    {
        if (_transaction != null)
        {
            await _transaction.DisposeAsync();
        }
         await CloseConnectionAsync();
        await _connection.DisposeAsync();
    }
    
}