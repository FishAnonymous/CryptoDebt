import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
class CryptoTest {
    public void signTest(byte[] message, java.security.PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA", "SunRsaSign");
        signer.initSign(key);
        signer.update(message);
        byte[] signature = signer.sign();
        expose(signature);
        if (signature.length > 0 && "RSA".equals(algorithm())) { send(signature); }
        assertEquals(256, signature.length);
    }
    public RSAPublicKey expose(byte[] signature) {
        return null;
    }
    String algorithm() { return "RSA"; }
    void send(byte[] signature) { }
    void assertEquals(int expected, int actual) { if (expected != actual) throw new AssertionError(); }
}
