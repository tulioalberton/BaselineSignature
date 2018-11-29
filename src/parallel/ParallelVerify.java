package parallel;

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


public class ParallelVerify {

	static ExecutorService verifierExecutor = null;
	static byte[] data = new byte[0];
	static byte[] signature;
	static Signature signEng;
	static int toVerify;
	static PublicKey publicKey;
	static PrivateKey privateKey;
	static AtomicInteger fim;
	static int cut;
	static ECDSAKeyLoader ecdsaKeyLoader;
	static RSAKeyLoader rsaKeyLoader;

	public static void main(String[] args) {
		if (args.length == 2 ){
			toVerify = Integer.parseInt(args[0]);
			cut =  Integer.parseInt(args[1]);
		}else {
			System.out.println("Usage: java -jar baseline.jar <iterations> <cut, to show progress>");
			System.out.println("Example: java -jar baseline.jar 100000 10000");
			System.exit(1);
		}
		
		
		for (int i = 0; i < data.length; i++) {
			Random rnd = new Random();
			data[i] = (byte) rnd.nextInt(1500);
		}
		
		
		//## RSA
		createAndSignRequestRSA();
		
		System.out.println("RSA signature test, sequential: " + toVerify);
		fim = new AtomicInteger(0);
		loopSequentialVerify();
		System.out.println("\n");
		
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

		//## ECDSA
		createAndSignRequestECDSA();
		fim = new AtomicInteger(0);
		System.out.println("ECDSA signature test, sequential: " + toVerify);
		loopSequentialVerify();
		System.out.println("\n");
		
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

	public static void createAndSignRequestECDSA() {

		Security.addProvider(new BouncyCastleProvider());
		try {
			ecdsaKeyLoader = new ECDSAKeyLoader(0, "", true, "SHA512withECDSA");
			privateKey = ecdsaKeyLoader.loadPrivateKey();
			publicKey = ecdsaKeyLoader.loadPublicKey();

			signEng = Signature.getInstance("SHA512withECDSA");
			signEng.initSign(privateKey);
			signEng.update(data);
			signature = signEng.sign();
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		}

	}
	public static void createAndSignRequestRSA() {
		try {

			rsaKeyLoader = new RSAKeyLoader(0, "", true, "SHA512withRSA");
				publicKey = rsaKeyLoader.loadPublicKey();
				privateKey = rsaKeyLoader.loadPrivateKey();

			signEng = Signature.getInstance("SHA1withRSA");
			signEng.initSign(privateKey);
			signEng.update(data);
			signature = signEng.sign();

			
		}
			// System.out.println("SignatureVerified: " + verified);
			catch (InvalidKeySpecException e) {
				e.printStackTrace();
			}catch ( CertificateException  e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (SignatureException e) {
				e.printStackTrace();
			}
		
	}

	public static void loopSequentialVerify() {
		fim.set(0);
		long start = System.currentTimeMillis();
		for (int i = 0; i <= toVerify; i++) {
			try {
				signEng.initVerify(publicKey);
				signEng.update(data);
				boolean r = signEng.verify(signature);
				// System.out.println("Verified: " + r);
			} catch (SignatureException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			}
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
			//System.out.println("Submiting: " + i);
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
				}finally {
					fim.incrementAndGet();
					latch.countDown();
					if (latch.getCount() % cut == 0)
						System.out.println("Progress, verified: " + fim.get());
				}
			});
		}
		try {
			latch.await();
			System.out.println("Finished...Latch: "+ latch.getCount() + ", Total verifies: " +fim.get());
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
