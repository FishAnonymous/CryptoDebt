import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
class Signer {
    public byte[] sign(byte[] message, java.security.PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA", "SunRsaSign");
        signer.initSign(key);
        signer.update(message);
        byte[] signature = signer.sign();
        byte[] frame = new byte[256];
        System.arraycopy(signature, 0, frame, 0, signature.length);
        save(signature);
        return signature;
    }
    public void save(byte[] signature) {
        if (signature.length != 256) throw new IllegalArgumentException();
    }
}
