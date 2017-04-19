package com.sphinx.rb.hmacapi.hmac;

import com.sphinx.rb.hmacapi.algorithm.HMACAlgorithm;
import com.sphinx.rb.hmacapi.exception.HMACException;
import com.sphinx.rb.hmacapi.exception.HMACHashException;
import com.sphinx.rb.hmacapi.exception.HMACKeyException;
import com.sphinx.rb.hmacapi.exception.HMACNonceException;
import com.sphinx.rb.hmacapi.hash.HMACHash;
import com.sphinx.rb.hmacapi.key.HMACKey;
import com.sphinx.rb.hmacapi.nonce.HMACNonce;

/**
 * HMAC Simples (sem sessão).
 *
 * @author Luan Lino Matias dos Santos
 *
 */
public class HMAC {

    /**
     *
     * @var HMACHash;
     */
    protected HMACHash hash;

    /**
     *
     * @var HMACAlgorithm
     */
    protected HMACAlgorithm algo;

    /**
     *
     * @var HMACKey
     */
    protected HMACKey key;

    /**
     * Identificador da chave a ser usada no HMAC
     *
     * @var string
     */
    protected String keyId;

    /**
     *
     * @var HMACNonce
     */
    protected HMACNonce nonce;

    /**
     *
     * @param algo HMACAlgorithm
     * @param hash HMACHash
     * @param key HMACKey
     * @param nonce HMACNonce
     */
    public HMAC(HMACAlgorithm algo, HMACHash hash, HMACKey key, HMACNonce nonce) {
        this.algo = algo;
        this.hash = hash;
        this.key = key;
        this.nonce = nonce;
    }

    /**
     * Calcula o HMAC a partir dos dados informados e dos parâmetros já
     * informados. Após informar KEYID.
     *
     * @param data string
     * @return string
     * @throws com.sphinx.rb.hmacapi.exception.HMACKeyException
     * @throws com.sphinx.rb.hmacapi.exception.HMACHashException
     */
    public String getHmac(String data) throws HMACKeyException, HMACHashException {
        /**
         * Delegar cálculo do HMAC
         */
        String hmac = this.algo.getHmac(this, data);

        return hmac;
    }

    /**
     *
     * @return string
     */
    public String __toString() {
        return getClass().getSimpleName();
    }

    /**
     *
     * @return string
     */
    public String getDescription() {
        return this.__toString() + "-" + this.algo.__toString() + "-" + this.hash.__toString() + "-" + this.nonce.__toString();
    }

    /**
     *
     * @return com.​sphinx.rb.​hmacapi.​hash.HMACHash;
     */
    public HMACHash getHashObject() {
        return this.hash;
    }

    /**
     *
     * @param data
     * @return string
     * @throws com.sphinx.rb.hmacapi.exception.HMACHashException
     */
    public String getHash(String data) throws HMACHashException {
        return this.hash.getHash(data);
    }

    /**
     * Verifica HMAC recebido após informar NONCE e KEYID
     *
     * @param data
     * @param hmac
     * @return boolean
     * @throws HMACException
     */
    public boolean validate(String data, String hmac) throws HMACException {

        String hmacLocal = this.getHmac(data);

        /**
         * Comparar as duas strings de hash
         */
        if (!hmac.equals(hmacLocal)) {
            throw new HMACException("HMAC informado é inválido");//, 1 );
        }
        return true;
    }

    /**
     * Informa valor do nonce
     *
     * @return string
     * @throws com.sphinx.rb.hmacapi.exception.HMACHashException
     */
    public String getNonceValue() throws HMACHashException {
        return this.nonce.getNonce();
    }

    /**
     *
     * @param nonceValue
     * @return HMAC
     * @throws com.sphinx.rb.hmacapi.exception.HMACNonceException
     */
    public HMAC setNonceValue(String nonceValue) throws HMACNonceException {
        /**
         * Verifica o NONCE. Dispara exceção caso o nonce seja recusado.
         */
        this.nonce.validate(nonceValue);

        /**
         * Registra nonce após validação
         */
        this.nonce.setNonce(nonceValue);
        return this;
    }
    
    /**
     * Retorna chave composto (que é gerada pelo HMACKey)
     *
     * @return string
     * @throws com.sphinx.rb.hmacapi.exception.HMACKeyException
     * @throws com.sphinx.rb.hmacapi.exception.HMACHashException
     */
    public String getCompositeKey() throws HMACKeyException, HMACHashException {
        return this.key.getCompositeKey(this);
    }

    /**
     *
     * @return com.sphinx.rb.hmacapi.algorithm.HMACAlgorithm
     */
    public HMACAlgorithm getAlgorithm() {
        return this.algo;
    }

    /**
     *
     * @param keyId
     * @return HMAC
     */
    public HMAC setKeyId(String keyId) {
        this.keyId = keyId;
        return this;
    }

    /**
     *
     * @return string
     */
    public String getKeyId() {
        return this.keyId;
    }

    public HMAC setNonce2Value(String nonce2) throws HMACNonceException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public boolean validate(String data, String hmac, int type) throws HMACException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public HMACSession startSession() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public String getHmac(String data, int type) throws HMACKeyException, HMACHashException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    protected String _getHmacKey() throws HMACException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public int getContador() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public HMACSession nextMessage() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public String getNonce2Value() throws HMACHashException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public int getDataType() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
   
}
