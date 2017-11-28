package com.sphinx.rb.hmachttpclient.client;

import com.sphinx.rb.hmacapi.exception.HMACException;
import com.sphinx.rb.hmacapi.exception.HMACHashException;
import com.sphinx.rb.hmacapi.exception.HMACKeyException;
import com.sphinx.rb.hmacapi.hmac.HMAC;
import com.sphinx.rb.hmacapi.hmac.HMACSession;
import com.sphinx.rb.hmachttpclient.util.JSONObject;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class HMACHttpClient {

    public static final int HMAC_HEADER = 0;
    public static final int HMAC_URI = 1;

    public static final int VERSION = 1;

    public static final String HEADER_NAME = "HMAC-Authentication";
    public static final String HEADER_NAME_SESSION = "HMAC-Authentication-Session";
    public static final String URI_PARAM_NAME = "hmacauthentication";

    public static final String GET = "GET";
    public static final String POST = "POST";
    public static final String PUT = "PUT";
    public static final String DELETE = "DELETE";
    public static final String OPTIONS = "OPTIONS";
    public static final String HEAD = "HEAD";
    public static final String TRACE = "TRACE";

    protected int hmacMode = HMACHttpClient.HMAC_HEADER;

    static HttpURLConnection requestGlobal = null;

    List<String> cookies = null;

    String method = "GET";

    private Map<String, String> headers = null;

    public HMACHttpClient(URL url) throws IOException, URISyntaxException {
        this.url = url.toURI().toString();
        this.headers = new LinkedHashMap<>();
        requestGlobal = (HttpURLConnection) url.openConnection();
    }

    /**
     *
     * @var HMAC
     */
    protected HMAC hmac = null;

    /**
     * Contador de mensagens enviadas
     *
     * @var int
     */
    protected int hmacContador = 0;

    /**
     * Indicar se sessão já foi iniciada
     *
     * @var bool
     */
    protected boolean hmacSession = false;

    /**
     * Indicar se URI já foi autenticada
     *
     * @var bool
     */
    protected boolean hmacSignedUri = false;

    protected String hmacSignedUriString = null;

    protected String message = "";

    protected String response = "";

    protected int responseCode = 0;

    protected String url = null;

    public int getResponseCode() {
        return responseCode;
    }

    /**
     * Iniciar sessão HMAC
     *
     * @throws java.io.IOException
     * @throws com.sphinx.rb.hmacapi.exception.HMACException
     * @throws java.net.URISyntaxException
     * @throws RuntimeException
     */
    protected void _startSession() throws IOException, HMACException, URISyntaxException {

        HttpURLConnection sessionRequest = (HttpURLConnection) new URL(url).openConnection();

        sessionRequest.setRequestMethod(this.method);

        /**
         * Início de sessão com header adicional (sem BODY)
         */
        sessionRequest.setRequestProperty(HEADER_NAME_SESSION, "Start");

        /**
         * Assinatura de início de sessão (igual assinatura sem sessão)
         */
        this._sign(sessionRequest, true);

        if (!this.method.equalsIgnoreCase(HMACHttpClient.GET)) {

            sessionRequest.setDoOutput(true);
            DataOutputStream httpout = new DataOutputStream(sessionRequest.getOutputStream());
            httpout.write("".getBytes());

        }

        if (cookies == null) {
            cookies = sessionRequest.getHeaderFields().get("Set-Cookie");
        }

        /**
         * Recupera resposta
         */
        StringBuilder body = new StringBuilder();
        BufferedReader br = null;
        try {
            br = new BufferedReader(new InputStreamReader(sessionRequest.getInputStream()));
        } catch (Exception e) {
            br = new BufferedReader(new InputStreamReader(sessionRequest.getErrorStream()));
        }
        String line = "";
        while ((line = br.readLine()) != null) {
            body.append(line);
        }
        br.close();

        /**
         * Recuperar header com assinatura HMAC
         */
        String headers = sessionRequest.getHeaderField(HEADER_NAME);

        if (headers == null) {
            throw new RuntimeException("HMAC não está presente na resposta");
        }

        String[] headerData = headers.split(":");//explode(':', header);
        if (headerData.length != 3) {
            throw new RuntimeException("HMAC da resposta é inválido (header incorreto)");
        }

        String versao = headerData[0];
        String nonce2 = headerData[1];
        String assinatura = headerData[2];

        /**
         * Verificar versão do protocolo
         */
        if (!versao.equals("" + this.VERSION)) {
            throw new RuntimeException("HMAC da resposta é inválido (versão incorreta)");
        }

        /**
         * Informar Nonce2 enviado pelo servidor
         */
        this.hmac.setNonce2Value(nonce2);
        /**
         * Verificar assinatura do NONCE2 enviado pelo servidor
         */
        this.hmac.validate(nonce2, assinatura, HMACSession.SESSION_RESPONSE);
        /**
         * Indicar início da sessão após validar resposta
         */
        this.hmac.startSession();
        this.hmacSession = true;

    }

    /**
     * Assinar requisição (sem sessão)
     *
     * @param request
     * @param startSession
     * @throws java.net.URISyntaxException
     * @throws java.io.IOException
     * @throws com.sphinx.rb.hmacapi.exception.HMACKeyException
     * @throws com.sphinx.rb.hmacapi.exception.HMACHashException
     * @throws RuntimeException
     */
    protected void _sign(HttpURLConnection request, boolean startSession) throws URISyntaxException, IOException, HMACKeyException, HMACHashException {

        if (this.hmacContador > 0) {
            throw new RuntimeException("HMAC sem sessão só pode enviar uma mensagem");
        }

        /**
         * Dados a assinar (versão 1 do protocolo)
         */
        String assinarDados
                = request.getRequestMethod() // método
                + request.getURL().toURI()// URI
                + (startSession ? "" : this.message);

        /**
         * Assinatura HMAC
         */
        String assinaturaHmac = null;

        if (this.hmac instanceof HMACSession) {
            assinaturaHmac = this.hmac.getHmac(assinarDados, HMACSession.SESSION_REQUEST);
        } else {
            assinaturaHmac = this.hmac.getHmac(assinarDados);
        }
        /**
         * Header de autenticação (protocolo versão 1)
         */
        String headerAuth = this.VERSION // versão do protocolo
                + ":" + this.hmac.getKeyId() // ID da chave/aplicação/cliente
                + ":" + this.hmac.getNonceValue() // nonce
                + ":" + assinaturaHmac;                // HMAC Hash

        request.setRequestProperty(HEADER_NAME, headerAuth);

    }

    /**
     * Assinar requisição (sem sessão)
     *
     * @param request
     * @throws java.net.URISyntaxException
     * @throws java.io.IOException
     * @throws com.sphinx.rb.hmacapi.exception.HMACKeyException
     * @throws com.sphinx.rb.hmacapi.exception.HMACHashException
     * @throws RuntimeException
     */
    protected void _sign(HttpURLConnection request) throws URISyntaxException, IOException, HMACKeyException, HMACHashException {
        this._sign(request, false);
    }

    /**
     * Assinar URI (sem sessão)
     *
     * @param request
     * @throws java.net.URISyntaxException
     * @throws java.io.IOException
     * @throws com.sphinx.rb.hmacapi.exception.HMACKeyException
     * @throws com.sphinx.rb.hmacapi.exception.HMACHashException
     * @throws RuntimeException
     */
    protected void _signUri(HttpURLConnection request) throws URISyntaxException, IOException, HMACKeyException, HMACHashException {

        if (this.hmacContador > 0) {
            throw new RuntimeException("HMAC sem sessão só pode enviar uma mensagem");
        }

        /**
         * Gera URI assinada
         */
        this.getSignedUri(request);

    }

    /**
     * Retornar URI com autenticação HMAC (HMACUriAdapter)
     *
     * @param request
     * @throws java.net.URISyntaxException
     * @throws java.io.IOException
     * @throws com.sphinx.rb.hmacapi.exception.HMACKeyException
     * @throws com.sphinx.rb.hmacapi.exception.HMACHashException
     * @throws RuntimeException
     * @return string
     */
    public String getSignedUri(HttpURLConnection request) throws URISyntaxException, IOException, HMACKeyException, HMACHashException {
        if (this.hmacSignedUri) {
            return this.hmacSignedUriString;
        }

        if (this.hmac == null) {
            throw new RuntimeException("HMAC é necessário para a requisição");
        }

        /**
         * Dados a assinar (versão 1 do protocolo)
         */
        String assinarDados = request.getURL().toURI()
                + ((this.message != null && !this.message.isEmpty()) ? (("" + request.getURL().toURI()).contains("?") ? "&" : "?") : "")
                + this.message;   // URI

        /**
         * Assinatura HMAC
         */
        String assinaturaHmac = null;
        if (this.hmac instanceof HMACSession) {
            assinaturaHmac = this.hmac.getHmac(assinarDados, HMACSession.SESSION_REQUEST);
        } else {
            assinaturaHmac = this.hmac.getHmac(assinarDados);
        }
        /**
         * Parâmetro de autenticação (protocolo versão 1)
         */
        String authParam = this.VERSION // versão do protocolo
                + ":" + this.hmac.getKeyId() // ID da chave/aplicação/cliente
                + ":" + this.hmac.getNonceValue() // nonce
                + ":" + assinaturaHmac;                // HMAC Hash
        /**
         * Acrescentar parâmetro HMAC na URI original
         */
        this.message += "&" + this.URI_PARAM_NAME + "=" + authParam;//.setParams(queryString);

        String uri = request.getURL().toURI().toString()
                + ((this.message != null && !this.message.isEmpty()) ? (("" + request.getURL().toURI().toString()).contains("?") ? "&" : "?") : "")
                + message;   // URI

        this.hmacSignedUriString = uri;
        this.hmacSignedUri = true;

        return uri;
    }

    public String getUrl() {
        return this.url;
    }

    public String getSignedUri() {
        return this.hmacSignedUriString;
    }

    /**
     * Assinar requisição (com sessão)
     *
     * @param request
     * @throws java.net.URISyntaxException
     * @throws java.io.IOException
     * @throws com.sphinx.rb.hmacapi.exception.HMACKeyException
     * @throws com.sphinx.rb.hmacapi.exception.HMACHashException
     * @throws RuntimeException
     */
    protected void _signSession(HttpURLConnection request) throws URISyntaxException, IOException, HMACKeyException, HMACHashException {

        /**
         * Dados a assinar (versão 1 do protocolo)
         */
        String assinarDados
                = request.getRequestMethod() // método
                + request.getURL().toURI()// URI
                + this.message;
        /**
         * Assinatura HMAC
         */
        String assinaturaHmac = this.hmac.getHmac(assinarDados, HMACSession.SESSION_MESSAGE);

        /**
         * Header de autenticação (protocolo versão 1)
         */
        String headerAuth = this.VERSION // versão do protocolo
                + ":" + assinaturaHmac;                // HMAC Hash

        request.setRequestProperty(this.HEADER_NAME, headerAuth);

    }

    /**
     * Verificar assinatura da resposta do servidor (sem sessão)
     *
     * @param response
     * @throws java.io.IOException
     * @throws com.sphinx.rb.hmacapi.exception.HMACException
     * @throws RuntimeException
     */
    protected void _verify(HttpURLConnection response) throws IOException, HMACException {
        /**
         * Recuperar header com assinatura HMAC
         */
        String headers = response.getHeaderField(this.HEADER_NAME);

        if (headers == null || headers.length() <= 0) {
            throw new RuntimeException("HMAC não está presente na resposta");
        }

        String[] headerData = headers.split(":");

        if (headerData.length != 2) {
            throw new RuntimeException("HMAC da resposta é inválido (header incorreto)");
        }

        String versao = headerData[0];
        String assinatura = headerData[1];

        /**
         * Verificar versão do protocolo
         */
        if (!versao.equals("" + VERSION)) {
            throw new RuntimeException("HMAC da resposta é inválido (versão incorreta)");
        }

        /**
         * Verificar assinatura
         */
        if (this.hmac instanceof HMACSession) {
            this.hmac.validate(this.response, assinatura, HMACSession.SESSION_MESSAGE);
        } else {
            this.hmac.validate(this.response, assinatura);
        }

    }

    /**
     *
     * Acrescenta HEADER para autenticação HMAC antes de enviar a requisição.
     * Verificar HEADER HMAC na resposta antes de devolver a resposta.
     *
     * @return Retorna uma string com a resposta da requisição ou null, caso
     * haja falha na requisição.
     *
     * @throws java.io.IOException
     * @throws com.sphinx.rb.hmacapi.exception.HMACException
     * @throws java.net.URISyntaxException
     */
    public String send() throws IOException, HMACException, URISyntaxException {

        String detalhes;

        if (this.hmac == null) {
            throw new RuntimeException("HMAC é necessário para a requisição");
        }

        requestGlobal = (HttpURLConnection) new URL(url).openConnection();
        requestGlobal.setRequestMethod(this.method);

        /**
         * Verificar se é com ou sem sessão
         */
        if (this.hmac instanceof HMACSession) {
            /**
             * Iniciar sessão
             */
            if (!this.hmacSession) {
                this._startSession();
            }

            /**
             * Assinar requisição
             */
            this._signSession(requestGlobal);

        } else {

            /**
             * Assinar requisição
             */
            switch (this.hmacMode) {
                case HMAC_URI:
                    this._signUri(requestGlobal);
                    break;
                case HMAC_HEADER:
                default:
                    this._sign(requestGlobal);
            }

        }

        /**
         * Enviar requisição
         */
        if (this.method.equalsIgnoreCase(HMACHttpClient.GET)) {
            url = hmacSignedUriString;
            requestGlobal = (HttpURLConnection) new URL(url).openConnection();
        }

        StringBuilder body = new StringBuilder();

        if (cookies != null) {
            for (String cookie : cookies) {
                requestGlobal.setRequestProperty("Cookie", cookie);
            }
        }
        requestGlobal.setDoOutput(true);

        // Seta os Headers
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            requestGlobal.setRequestProperty(entry.getKey(), entry.getValue());
        }

        if (!this.method.equalsIgnoreCase(HMACHttpClient.GET)) {

            DataOutputStream httpOut = new DataOutputStream(requestGlobal.getOutputStream());
            httpOut.write(this.message.getBytes("UTF-8"));
            httpOut.flush();
            httpOut.close();

        }

        if (cookies == null) {
            cookies = requestGlobal.getHeaderFields().get("Set-Cookie");
        }

        /**
         * Recupera resposta
         */
        BufferedReader br = null;
        try {
            br = new BufferedReader(new InputStreamReader(requestGlobal.getInputStream()));
        } catch (Exception e) {
            br = new BufferedReader(new InputStreamReader(requestGlobal.getErrorStream()));
        }
        String line = "";
        while ((line = br.readLine()) != null) {
            body.append(line);
        }
        br.close();

        response = body.toString();

        /**
         * Verificar se servidor informou erro de HMAC
         */
        responseCode = requestGlobal.getResponseCode();
        if (responseCode == 401) {
            detalhes = "";

            JSONObject json = new JSONObject(body.toString());

            if (json.length() <= 0) {
                /**
                 * Erro 401 não gerado pelo HMAC no servidor
                 */
                detalhes = body.toString();

            } else if (!json.has("detail")) {
                /**
                 * JSON não foi gerado pelo HMAC Server
                 */
                detalhes = body.toString();
            } else {
                detalhes = (String) json.opt("detail");

                /**
                 * Alertar da necessidade de início de sessão para comunicação
                 * com URI
                 */
                if (detalhes.contains("HMAC Authentication required")) {
                    if (this.hmac instanceof HMACSession) {
                        detalhes += " (sessão HMAC expirou)";
                    } else {
                        detalhes += " (servidor requer HMAC com sessão)";
                    }
                } else if (detalhes.contains("5 - Sessão HMAC não iniciada")) {
                    if (this.hmac instanceof HMACSession) {
                        detalhes += " (sessão HMAC expirou)";
                    } else {
                        detalhes += " (servidor requer HMAC com sessão)";
                    }
                }

                /**
                 * Detalhes adicionais enviados pelo servidor
                 */
                if (json.has("hmac")) {
                    detalhes += " ['" + json.optString("hmac") + "', v'" + json.optString("version") + "']";
                }
            }

            throw new RuntimeException("Erro HMAC remoto: " + detalhes + " - Code :" + 401);
        }

        /**
         * Verificar assinatura da resposta, se for resposta de sucesso (2xx)
         */
        if (requestGlobal.getResponseCode() >= 200 && requestGlobal.getResponseCode() <= 299) {

            this._verify(requestGlobal);
        }

        /**
         * Incrementar contador interno após validar resposta
         */
        if (this.hmac instanceof HMACSession) {
            this.hmacContador++;
            this.hmac.nextMessage(); // Incrementar contagem na sessão após validar resposta
        }
        return body.toString();
    }

    public void setRawBody(String messageToSend) {
        this.message = messageToSend;
    }

    public String getResponse() {
        return this.response;
    }

    public List<String> getCookies() {
        return this.cookies;
    }

    public void setCookies(List<String> cookies) {
        this.cookies = cookies;
    }

    /**
     *
     * @param hmac
     * @return HMACHttpClient
     */
    public HMACHttpClient setHmac(HMAC hmac) {
        this.hmac = hmac;
        return this;
    }

    /**
     *
     * @return HMAC
     */
    public HMAC getHmac() {
        return this.hmac;
    }

    /**
     *
     * @param modo
     * @return HMACHttpClient
     */
    public HMACHttpClient setHmacMode(int modo) {
        this.hmacMode = modo;
        return this;
    }

    /**
     *
     * @return int
     */
    public int getHmacMode() {
        return this.hmacMode;
    }

    public String getMethod() {
        return requestGlobal.getRequestMethod();
    }

    public void setMethod(String method) throws ProtocolException {
        this.method = method;
        requestGlobal.setRequestMethod(method);
    }

    public Map<String, List<String>> getHeaderFields() {
        return requestGlobal.getHeaderFields();
    }

    public void setRequestProperty(String key, String value) {
        headers.put(key, value);
    }

}
