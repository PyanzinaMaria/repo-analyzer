using System.Security.Cryptography;

public class Digest {
    public static byte[] Fingerprint(byte[] data) {
        using var hash = SHA256.Create();
        return hash.ComputeHash(data);
    }
}
