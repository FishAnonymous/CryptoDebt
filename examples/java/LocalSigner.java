import java.security.Signature;
class LocalSigner {
    static Signature create() throws Exception {
        return Signature.getInstance("SHA256withRSA");
    }
}
