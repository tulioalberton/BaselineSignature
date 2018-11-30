package keyloader;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;


public class ECDSAKeyLoader{

	private PrivateKey privateKey = null;

	//Bouncy Castle | 256 key size
	private static final String PRIVATE_KEY = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgMMpfKtHS5ZlgHDPj3TG41Y0t5r9NIzx7p4YPZxn5gBmgCgYIKoZIzj0DAQehRANCAAQkD2DTG37xnxtcMMLJMiUCyObUdVJE+rMM9WQ1Z3sjtIZchN8Xefr02Ag+giXGLej862qu3v4/fy6UGJNAHNx3";
	private static final String PUBLIC_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJA9g0xt+8Z8bXDDCyTIlAsjm1HVSRPqzDPVkNWd7I7SGXITfF3n69NgIPoIlxi3o/Otqrt7+P38ulBiTQBzcdw==";

	//Bouncy Castle | 384 key size
	//private static final String PRIVATE_KEY = "MIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDAgJ7PlzZFc8/rsMTODSsQgenL2+WDxGjohmwGSLe8wp0+dYX8x2M2CidHdjzQu41qgBwYFK4EEACKhZANiAASFk9m7oKkuGqHg+BDMo51XbDnvIahxmfcagDgOvU/plgjpyuoY74eJit2LlLhLyKzVq0Rmpr1dZAuQWhlZfmlvdv0RhScaSaOiea54VdO8ZhdHzHHDwZQkJiSJQAuWOv0=";
	//private static final String PUBLIC_KEY = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEhZPZu6CpLhqh4PgQzKOdV2w57yGocZn3GoA4Dr1P6ZYI6crqGO+HiYrdi5S4S8is1atEZqa9XWQLkFoZWX5pb3b9EYUnGkmjonmueFXTvGYXR8xxw8GUJCYkiUALljr9";

	//Bouncy Castle | 521 key size
	//private static final String PRIVATE_KEY = "MIH3AgEAMBAGByqGSM49AgEGBSuBBAAjBIHfMIHcAgEBBEIBlz6dy43Dp2XHkJzP00oY4japCVdVjYqUZdmDJwTnNfPCmiBA362OO8XgHzkSoz11W/YhXN3NNyBZg0gWNC1E4ZmgBwYFK4EEACOhgYkDgYYABAH0rMKko/e9Wp8f0G01SCbQaRBkZ/9PvxBKG3GbFUFeR5TiCf1GH8UNLHn5q6+ayD9RfhtOuSj2JuLKzZwAFNo12QAPXa/COqKxdwzoLnUcc81i1I/NEsgVp4eqHjs4UPzP9mvWE+D+XqXAqEU8cK+CMA9IXvdIrUU/szSvkhWT5nw0EA==";
	//private static final String PUBLIC_KEY = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB9KzCpKP3vVqfH9BtNUgm0GkQZGf/T78QShtxmxVBXkeU4gn9Rh/FDSx5+auvmsg/UX4bTrko9ibiys2cABTaNdkAD12vwjqisXcM6C51HHPNYtSPzRLIFaeHqh47OFD8z/Zr1hPg/l6lwKhFPHCvgjAPSF73SK1FP7M0r5IVk+Z8NBA=";


	public ECDSAKeyLoader() {}

	public PublicKey loadPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, NoSuchProviderException {
		return getPublicKeyFromString(PUBLIC_KEY);
	}

	public PrivateKey loadPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		return getPrivateKeyFromString(PRIVATE_KEY);
	}

	private PrivateKey getPrivateKeyFromString(String key)
			throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
		EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(key));
		privateKey = keyFactory.generatePrivate(privateKeySpec);
		return privateKey;
	}

	private PublicKey getPublicKeyFromString(String key)
			throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.decodeBase64(key));
		PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
		return publicKey;
	}

}
