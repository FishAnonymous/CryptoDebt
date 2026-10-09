import java.security.Signature;
class LocalSigner {
    static Signature create() throws Exception {
        return Signature.getInstance(CryptoPolicy.signingSuite0());
    }
}
