package com.sphinx.rb.hmacapi.nonce;

import com.sphinx.rb.hmacapi.exception.HMACHashException;
import com.sphinx.rb.hmacapi.exception.HMACNonceException;
import com.sphinx.rb.hmacapi.hash.JAVAHash;
import java.util.Random;

/**
 * Nonce com TIME STAMP e parte pseudo aleatória.
 *
 * @author Luan Lino Matias dos Santos
 *
 */
public class SimpleTSNonce extends HMACNonce {

    /**
     * Maior diferença (em segundos) entre o TimeStamp do nonce a ser verificado
     * e o timestamp atual.
     *
     * @var number
     */
    int TIMEOUT = 900; // segundos

    /**
     * Número de dígitos pseudo-aleatórios antes do TimeStamp
     *
     * @var number
     */
    int numDigitosAleatorios = 0;

    /**
     *
     * @param numDigitosAleatorios
     */
    public SimpleTSNonce(int numDigitosAleatorios) {
        this.numDigitosAleatorios = numDigitosAleatorios;
    }

    /**
     *
     * @return String
     * @throws com.sphinx.rb.hmacapi.exception.HMACHashException
     * @see com.​sphinx.rb.​hmacapi.​nonce.HMACNonce.generate()
     */
    @Override
    public String generate() throws HMACHashException {
        JAVAHash hash = null;

        hash = new JAVAHash("SHA-1");

        /**
         * Gerar parte pseudo-aleatória antes do time stamp
         */
        Random random = new Random();
        String rand = "";
        if (this.numDigitosAleatorios > 0) {
            rand = hash.getHash("" + random.nextInt()); // SHA1 gera 40 caracteres
            rand = rand.substring(random.nextInt(39 - this.numDigitosAleatorios), this.numDigitosAleatorios);
        }

        this.nonce = rand + (String.valueOf(System.currentTimeMillis())).substring(0, 10);

        return this.nonce;
    }

    /**
     *
     * @param nonce
     * @return boolean
     * @throws com.sphinx.rb.hmacapi.exception.HMACNonceException
     * @see com.​sphinx.rb.​hmacapi.​nonce.HMACNonce.validate()
     */
    @Override
    public boolean validate(String nonce) throws HMACNonceException {

        if (nonce == null) {
            nonce = this.nonce;
        }

        /**
         * Extrair TIMESTAMP do nonce
         */
        int timestamp = Integer.parseInt(nonce.substring(0, this.numDigitosAleatorios));
        //String timestamp = substr ( nonce, this.numDigitosAleatorios ) + 0;
        String now = "" + System.currentTimeMillis();

        now = now.substring(0, 10);

        int nowI = Integer.parseInt(now);

        if (((timestamp - nowI) <= (TIMEOUT / 2)) == false) {
            throw new HMACNonceException("Simple TS Nonce fora do intervalo aceitável");//, 1 );

        }
        return true;
    }
}
