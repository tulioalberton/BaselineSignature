package baseline;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import bftsmart.reconfiguration.util.ECDSAKeyLoader;
import bftsmart.reconfiguration.util.RSAKeyLoader;

public class Baseline {

	static ExecutorService verifierExecutor = null;
	static byte[] data = new byte[0];
	static byte[] signature;
	static Signature signEng;
	static int toVerify;
	static PublicKey publicKey;
	static PrivateKey privateKey;
	static AtomicInteger fim;
	static int cut;
	static String signBaseline;
	static String typeBaseline;
	static boolean both = false,  parallel = false, sequential = false;
	static boolean all = false, ecdsa = false, rsa = false;
	static ECDSAKeyLoader ecdsaKeyLoader;
	static RSAKeyLoader rsaKeyLoader;
	//static SunECKeyLoader sunECKeyLoader;
	
	public static void main(String[] args)throws NoSuchAlgorithmException, InvalidKeyException,
	SignatureException, InvalidKeySpecException, CertificateException, IOException {
		if (args.length == 4) {
			toVerify = Integer.parseInt(args[0]);
			cut = toVerify / Integer.parseInt(args[1]);
			signBaseline = args[2];
			typeBaseline = args[3];
		} else {
			System.out.println("Usage: java -jar baseline.jar <iterations> "
					+ "<% ~ progress> <signature: all | ecdsa | rsa> <type: both | parallel | sequential>");
			System.out.println("Example: java -jar baseline.jar 100000 20 rsa parallel");
			System.exit(1);
		}

		for (int i = 0; i < data.length; i++) {
			Random rnd = new Random();
			data[i] = (byte) rnd.nextInt(1500);
		}

		switch (typeBaseline) {
		case "parallel":
			parallel = true;
			break;
		case "sequential":
			sequential = true;
			break;
		default:
			both = true;
			break;
		}

		switch (signBaseline) {
		case "ecdsa":
			ecdsa = true;
			break;
		case "rsa":
			rsa = true;
			break;
		default:
			all = true;
			break;
		}
		if(all) {
			rsaTest();
			ecdsaTest();
		}else if (rsa) {
			rsaTest();
		}
		else if(ecdsa){
			ecdsaTest();
		}
	}

	public static void ecdsaTest() throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException, InvalidKeySpecException, CertificateException, IOException {
		// ## ECDSA
		createAndSignRequestECDSA();
		if (sequential) {
			fim = new AtomicInteger(0);
			System.out.println("ECDSA signature test, sequential: " + toVerify);
			loopSequentialVerify();
			System.out.println("\n");
		}
		if (parallel) {
			System.out.println("ECDSA signature test, parallel: " + toVerify + " ## Executor: newCachedThreadPool");
			verifierExecutor = Executors.newCachedThreadPool();
			fim = new AtomicInteger(0);
			loopParallelVerify();
			verifierExecutor.shutdown();
			System.out.println("\n");

			System.out.println("ECDSA signature test, parallel: " + toVerify + " ## Executor: newFixedThreadPool");
			fim = new AtomicInteger(0);
			verifierExecutor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
			loopParallelVerify();
			verifierExecutor.shutdown();
		}
	}

	public static void rsaTest() throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException, InvalidKeySpecException, CertificateException, IOException {
		// ## RSA
		createAndSignRequestRSA();

		if (sequential) {
			System.out.println("RSA signature test, sequential: " + toVerify);
			fim = new AtomicInteger(0);
			loopSequentialVerify();
			System.out.println("\n");
		}
		if (parallel) {
			System.out.println("RSA signature test, parallel: " + toVerify + " ## Executor: newCachedThreadPool");
			verifierExecutor = Executors.newCachedThreadPool();
			fim = new AtomicInteger(0);
			loopParallelVerify();
			verifierExecutor.shutdown();
			System.out.println("\n");

			System.out.println("RSA signature test, parallel: " + toVerify + " ## Executor: newFixedThreadPool");
			verifierExecutor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
			fim = new AtomicInteger(0);
			loopParallelVerify();
			verifierExecutor.shutdown();
			System.out.println("\n");
		}

	}


	/*public static void createAndSignRequestSunEC() throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException, InvalidKeySpecException, CertificateException, IOException {

		Security.addProvider(new Sun());
		ecdsaKeyLoader = new SunECKeyLoader(0, "", true, "SHA512withECDSA");
		privateKey = ecdsaKeyLoader.loadPrivateKey();
		publicKey = ecdsaKeyLoader.loadPublicKey();

		signEng = Signature.getInstance("SHA512withECDSA");
		signEng.initSign(privateKey);
		signEng.update(data);
		signature = signEng.sign();
	}*/
	
	public static void createAndSignRequestECDSA() throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException, InvalidKeySpecException, CertificateException, IOException {

		Security.addProvider(new BouncyCastleProvider());
		ecdsaKeyLoader = new ECDSAKeyLoader(0, "", true, "SHA512withECDSA");
		privateKey = ecdsaKeyLoader.loadPrivateKey();
		publicKey = ecdsaKeyLoader.loadPublicKey();

		signEng = Signature.getInstance("SHA512withECDSA");
		signEng.initSign(privateKey);
		signEng.update(data);
		signature = signEng.sign();
	}

	public static void createAndSignRequestRSA() throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException, InvalidKeySpecException, CertificateException, IOException {

		rsaKeyLoader = new RSAKeyLoader(0, "", true, "SHA512withRSA");
		publicKey = rsaKeyLoader.loadPublicKey();
		privateKey = rsaKeyLoader.loadPrivateKey();

		signEng = Signature.getInstance("SHA1withRSA");
		signEng.initSign(privateKey);
		signEng.update(data);
		signature = signEng.sign();
	}

	public static void loopSequentialVerify() throws SignatureException, InvalidKeyException {
		fim.set(0);
		long start = System.currentTimeMillis();
		for (int i = 0; i <= toVerify; i++) {
			signEng.initVerify(publicKey);
			signEng.update(data);
			boolean r = signEng.verify(signature);
			if (fim.incrementAndGet() % cut == 0)
				System.out.println("Progress, verified: " + fim.get());
		}
		long end = System.currentTimeMillis();
		long elapsed = (end - start) / 1000;
		if (elapsed > 0) {
			long opsPerSecond = toVerify / elapsed;
			System.out.println("Elapsed (sequential): " + elapsed + "s, ### verifies / s: " + opsPerSecond);
		}
	}

	public static void loopParallelVerify() {

		long start = System.currentTimeMillis();

		final CountDownLatch latch = new CountDownLatch(toVerify);
		fim.set(0);
		for (int i = 0; i < toVerify; i++) {
			// System.out.println("Submiting: " + i);
			verifierExecutor.submit(() -> {
				try {
					signEng.initVerify(publicKey);
					signEng.update(data);
					signEng.verify(signature);
					// System.out.println("Verified: " + r);

				} catch (SignatureException e) {
					e.printStackTrace();
				} catch (InvalidKeyException e) {
					e.printStackTrace();
				} finally {
					fim.incrementAndGet();
					latch.countDown();
					if (latch.getCount() % cut == 0)
						System.out.println("Progress, verified: " + fim.get());
				}
			});
		}
		try {
			latch.await();
			System.out.println("Finished...Latch: " + latch.getCount() + ", Total verifies: " + fim.get());
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		long end = System.currentTimeMillis();
		long elapsed = (end - start) / 1000;
		if (elapsed > 0) {
			long opsPerSecond = toVerify / elapsed;
			System.out.println("Elapsed (parallel): " + elapsed + "s, ### verifies / s: " + opsPerSecond);
		}
		verifierExecutor.shutdown();
	}

}
