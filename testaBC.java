import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.Charset;
import java.security.Security;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class testaBC {
	public static void main(String[] args) throws IOException {
		BufferedReader br = null;
		BufferedWriter bw = null;

		try {
			Security.insertProviderAt(new BouncyCastleProvider(), 1);

			BlockCipher engine = new AESEngine();

			BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine));

			String keyString = "s6v9y$B&E)H@McQfTjWnZq4t7w!z%C*F";
			byte[] key = keyString.getBytes();
			cipher.init(true, new KeyParameter(key));

			InputStream fis = new FileInputStream("texto-claro.txt");
			Reader isr = new InputStreamReader(fis);
			br = new BufferedReader(isr);

			OutputStream fos = new FileOutputStream("texto-cifrado.bin");
			Writer osw = new OutputStreamWriter(fos);
			bw = new BufferedWriter(osw);

			String linha = br.readLine();

			while (!(linha == null || linha.isEmpty())) {

				byte[] input = linha.getBytes(Charset.forName("ISO-8859-1"));

				byte[] cipherText = new byte[cipher.getOutputSize(input.length)];

				int outputLen = cipher.processBytes(input, 0, input.length, cipherText, 0);

				cipher.doFinal(cipherText, outputLen);

				bw.write(new String(cipherText, Charset.forName("ISO-8859-1")));
				bw.newLine();
				bw.flush();
				linha = br.readLine();
			}
		} catch (CryptoException e) {
			e.printStackTrace();
		} finally {
			if(br != null) br.close();
			if(bw != null) bw.close();
		}
	}
}