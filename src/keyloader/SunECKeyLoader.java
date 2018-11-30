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

public class SunECKeyLoader {

	//SunEC secp256r1
	private static final String PRIVATE_KEY = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCzKihManx3ughKcT5x8mdNj9GFGxH1UvKVKm8LqbDlig==";
	private static final String PUBLIC_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqDGm5E0cL8w427d/3NujzqZPYvLR+dd6ZzyZaCmE3u9lN5lSjh7ia3xpxW0R20Gv6dxitwLBy02PhXsUk21B1Q==";

	//SunEC secp384r1
	//private static final String PRIVATE_KEY = "ME4CAQAwEAYHKoZIzj0CAQYFK4EEACIENzA1AgEBBDAmegdlkADA/8rbG0CpuZdO1fnHOngWnBwOH04XFk0ZX/GNOTaYTtVMHuI/fuhALDk=";
	//private static final String PUBLIC_KEY = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFFMlwova3OBpWS9YsZvjnQAuoLGwZjAGpNKFspZAskB2vTnkBOAmgm1I9UTM45rT5OzLPdrv9p+Ry76ZkEx7MK4s2eCj1U7RsLInZ1fFkgCleTDVYx/1JHBMf0wcscKR";

	//SunEC secp521r1
	//private static final String PRIVATE_KEY = "MF8CAQAwEAYHKoZIzj0CAQYFK4EEACMESDBGAgEBBEHwZjYqD8oGXmtwvYtJI2mezVcU9hSKQHWc/LirGP/+oqVbnJQ8Unz6toGE8+WDXVFnIr6u4mmmV47L4/78Tmnu+w==";
	//private static final String PUBLIC_KEY = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAUsovGsGwA3FFEfUOK01+UF1LFq2U7rIxzJYuW0/HVK18unQOkpFwezKzvwcYeS3hli2VHxHr6PJm2mVuh4MGtxYA4/2h46Dk5qMl5dX65723/4mq9sEHk9xQp0XtMfeeDyFGplNQYvtJ7OcqerOb3bhKcCFgoGGSFv8wwWjSI0NyiSU=";

	public SunECKeyLoader() {}
	public PublicKey loadPublicKey()
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException,
			NoSuchProviderException{
				return getPublicKeyFromString(PUBLIC_KEY);
	}

	public PrivateKey loadPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException{
		return getPrivateKeyFromString(PRIVATE_KEY);
	}

	private PrivateKey getPrivateKeyFromString(String key)
			throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance("EC", "SunEC");
		EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(key));
		return keyFactory.generatePrivate(privateKeySpec);
	}

	private PublicKey getPublicKeyFromString(String key)
			throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		KeyFactory keyFactory = KeyFactory.getInstance("EC", "SunEC");
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.decodeBase64(key));
		PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
		return publicKey;
	}

}
