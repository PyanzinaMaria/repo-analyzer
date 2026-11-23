import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class Digest {
    static byte[] fingerprint(byte[] data) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }
}
