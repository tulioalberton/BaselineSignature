package baseline;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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

import keyloader.ECDSAKeyLoader;
import keyloader.RSAKeyLoader;
import keyloader.SunECKeyLoader;

public class Baseline {

	static ExecutorService verifierExecutor = null;
	static byte[] data = new byte[0];
	static byte[] signature;
	static Signature signEng;
	static int toVerify;
	static PublicKey publicKey;
	static PrivateKey privateKey;
	static AtomicInteger fim;
	static int cut=-1;
	static boolean showProgress=false;
	static String signBaseline;
	static String typeBaseline;
	static boolean both = false,  parallel = false, sequential = false;
	static boolean all = false, ecdsa = false, rsa = false, sunEC = false;
	static ECDSAKeyLoader ecdsaKeyLoader;
	static RSAKeyLoader rsaKeyLoader;
	static SunECKeyLoader sunECKeyLoader;
	
	public static void main(String[] args)throws NoSuchAlgorithmException, InvalidKeyException,
	SignatureException, InvalidKeySpecException, CertificateException, IOException, NoSuchProviderException {
		if (args.length == 4) {
			toVerify = Integer.parseInt(args[0]);
			showProgress = Boolean.parseBoolean(args[1]);
			if(showProgress)
				cut = (int)Math.round(toVerify * 0.25);
			signBaseline = args[2];
			typeBaseline = args[3];
		} else {
			System.out.println("Usage: java -jar baseline.jar <iterations> "
					+ "<show progress true|false> "
					+ "<signature: all | ecdsa | rsa | sunec> "
					+ "<type: both | parallel | sequential>");
			System.out.println("Example: java -jar baseline.jar 100000 false rsa both");
			System.exit(1);
		}

		for (int i = 0; i < data.length; i++) {
			Random rnd = new Random();
			data[i] = (byte) rnd.nextInt(1500);
		}

		switch (typeBaseline.toLowerCase()) {
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
		case "sunec":
			sunEC = true;
			break;
		default:
			System.out.println("\n#### Setting default test, all combinations. #### \n");
			all = true;
			break;
		}
		if(all) {
			doTest("RSA");
			doTest("SunEC");
			doTest("ECDSA");
		}
		else if (rsa) {
			doTest("RSA");
		}
		else if(ecdsa){
			doTest("ECDSA");
		}
		else if(sunEC){
			doTest("SunEC");
		}
	}

	
	public static void doTest(String whichOne) throws NoSuchAlgorithmException, InvalidKeyException,
	SignatureException, InvalidKeySpecException, CertificateException, IOException, NoSuchProviderException {
		switch (whichOne) {
		case "ECDSA":
			createAndSignRequestECDSA();
			break;
		case "RSA":
			createAndSignRequestRSA();
			break;
		case "SunEC":
			createAndSignRequestSunEC();
			break;
		default:
			System.out.println("Shall not fall here!");
			System.exit(1);
			break;
		}
		
		if (sequential || both) {
			fim = new AtomicInteger(0);
			System.out.println("\n"+whichOne+ " signature test, sequential: " + toVerify);
			loopSequentialVerify();
		}
		if (parallel || both) {
			System.out.println("\n"+whichOne+ " signature test, parallel: " + toVerify + " ## Executor: newCachedThreadPool");
			verifierExecutor = Executors.newCachedThreadPool();
			fim = new AtomicInteger(0);
			loopParallelVerify();
			verifierExecutor.shutdown();

			System.out.println("\n"+whichOne+ " signature test, parallel: " + toVerify + " ## Executor: newFixedThreadPool");
			fim = new AtomicInteger(0);
			verifierExecutor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
			loopParallelVerify();
			verifierExecutor.shutdown();
			
			System.out.println("\n"+whichOne+ " signature test, parallel: " + toVerify + " ## Executor: newStealingThreadPool");
			fim = new AtomicInteger(0);
			verifierExecutor = Executors.newWorkStealingPool(Runtime.getRuntime().availableProcessors());
			loopParallelVerify();
			verifierExecutor.shutdown();
		}
		System.out.println("");
		
	}

	public static void createAndSignRequestSunEC() throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException, InvalidKeySpecException, CertificateException, IOException, NoSuchProviderException {

		sunECKeyLoader = new SunECKeyLoader();
		privateKey = sunECKeyLoader.loadPrivateKey();
		publicKey = sunECKeyLoader.loadPublicKey();

		signEng = Signature.getInstance("SHA512withECDSA");
		signEng.initSign(privateKey);
		signEng.update(data);
		signature = signEng.sign();
	}
	
	public static void createAndSignRequestECDSA() throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException, InvalidKeySpecException, CertificateException, IOException, NoSuchProviderException {

		Security.addProvider(new BouncyCastleProvider());
		ecdsaKeyLoader = new ECDSAKeyLoader();
		privateKey = ecdsaKeyLoader.loadPrivateKey();
		publicKey = ecdsaKeyLoader.loadPublicKey();

		signEng = Signature.getInstance("SHA512withECDSA");
		signEng.initSign(privateKey);
		signEng.update(data);
		signature = signEng.sign();
	}

	public static void createAndSignRequestRSA() throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException, InvalidKeySpecException, CertificateException, IOException {

		rsaKeyLoader = new RSAKeyLoader();
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
		for (int i = 0; i < toVerify; i++) {
			signEng.initVerify(publicKey);
			signEng.update(data);
			boolean r = signEng.verify(signature);
			if (fim.incrementAndGet() % cut == 0 && showProgress)
				System.out.println("Progress, verified: " + fim.get());
		}
		long end = System.currentTimeMillis();
		long elapsed = (end - start) / 1000;
		if (elapsed > 0) {
			long opsPerSecond = toVerify / elapsed;
			System.out.println("Elapsed (sequential): " + elapsed + "s, ### verifications / s: " + opsPerSecond
					+ ".\nTotal verifications: " + fim.get());
		}else {
			System.out.println("Less than one second to execute all verifications.");
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
					if (latch.getCount() % cut == 0 && showProgress)
						System.out.println("Progress, verified: " + fim.get());
				}
			});
		}
		try {
			latch.await();
			//System.out.println("Finished...Latch: " + latch.getCount() + ", Total verifies: " + fim.get());
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		long end = System.currentTimeMillis();
		long elapsed = (end - start) / 1000;
		if (elapsed > 0) {
			long opsPerSecond = toVerify / elapsed;
			System.out.println("Elapsed (parallel): " + elapsed + "s, ### verifications / s: " + opsPerSecond
					+ ".\nTotal verifications: " + fim.get());
		}else {
			System.out.println("Less than one second to execute all verifications.");
		}
	}

}
