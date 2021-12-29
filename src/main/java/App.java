import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.io.InputStream;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.util.stream.IntStream;

public class App {
    public static void main(String[] args) {
        Provider provider = new BouncyCastleProvider();
        // 无界流
        IntStream.iterate(0, i -> i + 1)
                .forEach(i -> {
                    try {
                        keyFileLoad(provider);
                        // 每加载50次 打印JVM状态
                        if (i % 50 == 0) {
                            System.out.print("key file load times: " + i + " ");
                            printJvmStat();
                        }
                    } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    }
                });
    }

    public static void keyFileLoad(Provider provider) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("PKCS12", provider);
        InputStream keyFileInput = App.class.getClassLoader().getResourceAsStream("user-rsa.p12");
        String password = "111111";
        ks.load(keyFileInput, password.toCharArray());
    }

    public static void printJvmStat() {
        // Get current size of heap in bytes
        long heapSize = Runtime.getRuntime().totalMemory();
        // Get maximum size of heap in bytes. The heap cannot grow beyond this size.// Any attempt will result in an OutOfMemoryException.
        long heapMaxSize = Runtime.getRuntime().maxMemory();
        // Get amount of free memory within the heap in bytes. This size will increase // after garbage collection and decrease as new objects are created.
        long heapFreeSize = Runtime.getRuntime().freeMemory();

        long fullGc = 0;
        long fullGcTime = 0;
        for (GarbageCollectorMXBean gc : ManagementFactory.getGarbageCollectorMXBeans()) {
            if ("PS MarkSweep".equals(gc.getName())) {
                fullGc += gc.getCollectionCount();
                fullGcTime += gc.getCollectionTime();
            }
        }
        System.out.printf("heapSize=%s, heapFreeSize=%s  FGC=%s, FGCT=%s\n", heapSize, heapFreeSize, fullGc, fullGcTime);
    }

}
