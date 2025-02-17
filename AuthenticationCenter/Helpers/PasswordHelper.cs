using System.Security.Cryptography;

namespace AuthenticationCenter.Helpers;

public class PasswordHelper
{
    public static (string Hash, string salt) HashPassword(string password)
    {
        // Generar un salt único
        byte[] saltBytes = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(saltBytes);
        }

        string salt = Convert.ToBase64String(saltBytes);
        
        // Derivar la clave hash usando PBKDF2
        using (var rfc2898 = new Rfc2898DeriveBytes(password, saltBytes, 100000, HashAlgorithmName.SHA256))
        {
            byte[] hashBytes = rfc2898.GetBytes(32); // Generar un hash de 256 bits
            string hash = Convert.ToBase64String(hashBytes);
            return (hash, salt);
        }
    }
    // Método para verificar una contraseña contra un hash almacenado
    public static bool VerifyPassword(string password, string storedHash, string storedSalt)
    {
        byte[] saltBytes = Convert.FromBase64String(storedSalt);
        using (var rfc2898 = new Rfc2898DeriveBytes(password, saltBytes, 100000, HashAlgorithmName.SHA256))
        {
            byte[] hashBytes = rfc2898.GetBytes(32);
            string computedHash = Convert.ToBase64String(hashBytes);
            return computedHash == storedHash;
        }
        
    }
    
}