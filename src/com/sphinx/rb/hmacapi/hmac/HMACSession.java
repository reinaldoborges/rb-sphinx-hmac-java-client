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
 * HMAC com sessão
 *
 * @author Luan Lino Matias dos Santos
 *
 */
public class HMACSession extends HMAC {

    public final static int SESSION_REQUEST = 1;
    public final static int SESSION_RESPONSE = 2;
    public final static int SESSION_MESSAGE = 3;

    /**
     * Tipo da mensagem, utilizado para definir a formação da CHAVE HMAC
     *
     * @var number
     */
    protected int dataType = 0;

    /**
     * Nonce gerado pelo servidor para comunicação com sessão
     *
     * @var HMACNonce
     */
    protected HMACNonce nonce2;

    /**
     * Contador da mensagem na sessão
     *
     * @var number
     */
    protected int contador = 0;

    /**
     *
     * @param algo
     * @param hash
     * @param key
     * @param nonce
     * @param nonce2
     */
    public HMACSession(HMACAlgorithm algo, HMACHash hash, HMACKey key, HMACNonce nonce, HMACNonce nonce2) {
        super(algo, hash, key, nonce);
        this.nonce2 = nonce2;
    }

    /**
     * Sinalizar início da sessão.
     *
     * @return HMACSession
     */
    @Override
    public HMACSession startSession() {
        /**
         * Indicar próxima mensagem esperada
         */
        this.contador = 1;

        return this;
    }

    /**
     * Prepara chave a ser utilizada pelo HMAC Com sessão, utiliza também o
     * NONCE2 (gerado pelo servidor) e o CONTADOR da mensagem dentro da sessão
     *
     * @return string
     * @throws HMACException
     */
    @Override
    protected String _getHmacKey() throws HMACException {

        String hmacKey = null;
        /**
         * Detectar tipo de mensagem pelo estado da sessão
         */
        if (this.dataType == 0) {
            this.dataType = this.SESSION_REQUEST;
        }

        /**
         * Ajustar composição de acordo com o tipo da mensagem
         */
        switch (this.dataType) {

            case SESSION_REQUEST:
                /**
                 * Requisição de início de sessão: NONCE + KEY
                 */
                hmacKey = this.nonce.getNonce() + this.key.getKeyString(this.keyId);
                break;
            case SESSION_RESPONSE:
                /**
                 * Resposta à requisição de início de sessão: NONCE + KEY +
                 * NONCE2
                 */
                if (this.contador == 0) {
                    throw new HMACException("Sessão HMAC não iniciada");//, 101 );
                }
                hmacKey = this.nonce.getNonce() + this.key.getKeyString(this.keyId) + this.nonce2.getNonce();
                break;
            case SESSION_MESSAGE:
                /**
                 * Mensagens dentro da sessão: NONCE + KEY + CONTADOR + NONCE2
                 */
                hmacKey = this.nonce.getNonce() + this.key.getKeyString(this.keyId) + this.contador + this.nonce2.getNonce();
                break;
            default:
                throw new HMACException("Tipo de mensagem HMAC desconhecida");//, 102 );
        }

        return hmacKey;
    }

    /**
     * Informa valor do nonce2 (gerado pelo servidor)
     *
     * @return string
     * @throws com.sphinx.rb.hmacapi.exception.HMACHashException
     */
    @Override
    public String getNonce2Value() throws HMACHashException {
        return this.nonce2.getNonce();
    }

    /**
     *
     * @return number
     */
    @Override
    public int getContador() {
        return this.contador;
    }

    /**
     * Retorna chave composto (que é gerada pelo HMACKey)
     *
     * @return string
     * @throws com.sphinx.rb.hmacapi.exception.HMACKeyException
     * @throws com.sphinx.rb.hmacapi.exception.HMACHashException
     */
    @Override
    public String getCompositeKey() throws HMACKeyException, HMACHashException {
        return this.key.getCompositeKey(this);
    }

    /**
     * (non-PHPdoc)
     *
     * @param data
     * @param type
     * @return
     * @throws com.sphinx.rb.hmacapi.exception.HMACKeyException
     * @throws com.sphinx.rb.hmacapi.exception.HMACHashException
     * @see HMAC.getHmac()
     */
    @Override
    public String getHmac(String data, int type) throws HMACKeyException, HMACHashException {
        if (type > 0) {
            this.dataType = type;
        }

        /**
         * Delegar cálculo do HMAC
         */
        String hmac = this.algo.getHmac(this, data);

        return hmac;
    }

    /**
     *
     * @param data
     * @param hmac
     * @param type
     * @return
     * @throws com.sphinx.rb.hmacapi.exception.HMACException
     */
    @Override
    public boolean validate(String data, String hmac, int type) throws HMACException {
        if (type > 0) {
            this.dataType = type;
        }

        boolean validate = validate(data, hmac);

        return validate;
    }

    /**
     *
     * @return number
     */
    @Override
    public int getDataType() {
        return this.dataType;
    }

    /**
     * Incrementar contador, APÓS validar mensagem recebida e calcular HMAC da
     * resposta
     *
     * @return HMACSession
     */
    @Override
    public HMACSession nextMessage() {
        this.contador++;

        return this;
    }

    /**
     *
     * @param nonceValue
     * @return HMAC
     * @throws com.sphinx.rb.hmacapi.exception.HMACNonceException
     */
    @Override
    public HMAC setNonce2Value(String nonceValue) throws HMACNonceException {
        /**
         * Verifica o NONCE. Dispara exceção caso o nonce seja recusado.
         */
        this.nonce2.validate(nonceValue);

        /**
         * Registra nonce após validação--
         */
        this.nonce2.setNonce(nonceValue);
        return this;
    }

    /**
     *
     * @return description
     * @see HMAC.getDescription()
     */
    @Override
    public String getDescription() {
        return super.getDescription() + '-' + this.nonce2;
    }
}
