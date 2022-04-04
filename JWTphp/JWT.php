<?php
namespace JWTphp\JWT;
require_once('./Exception.php');
require_once('./Enums/jwt.php');
use JWTphp\Exceptions;
use JWTphp\Enums\JWT as Enums;
use OpenSSLAsymmetricKey;

/**
 * Undocumented class
 */
class JWTElements
{
    public array $header;
    public array $payload;
    public string $signature;

    /**
     * Create a JWTElements object, which will convert given elements to array object types
     * which can be publically accessed.
     *
     * @param string|array $header The JOSE Header
     * @param string|array $payload The payload of the given JWT
     * @param string $signature The signature of the JWT, based on the algorithm
     */
    function __construct(string|array $header, string|array $payload, string $signature)
    {
        switch (gettype($header))
        {
            case 'string':
                $this->header = JWTElements::Base64ToArray($header);
                break;
            case 'array':
                $this->header = $header;
                break;
        }
        switch (gettype($payload))
        {
            case 'string':
                $this->payload = JWTElements::Base64ToArray($payload);
                break;
            case 'array':
                $this->payload = $payload;
                break;
        }
        $this->signature = $signature;
    }

    /**
     * Undocumented function
     *
     * @param string $input
     * @return array
     */
    static function Base64ToArray(string $input): ?array
    {
        return json_decode(base64_decode(str_pad(strtr($input, '-_', '+/'), strlen($input) % 4, '=', STR_PAD_RIGHT)), true);
    }

    /**
     * Undocumented function
     *
     * @param array $input
     * @return string
     */
    static function ArrayToBase64(array $input): string
    {
        return rtrim(strtr(base64_encode(json_encode($input)), '+/', '-_'), '=');
    }

    /**
     * Undocumented function
     *
     * @param string $secret
     * @return boolean
     * @throws Exceptions\NotSupportedException
     */
    public function VerifyWithSecret(string $secret): bool
    {
        switch ($this->header['alg'])
        {
            case Enums\Algorithm::RS256:
            case Enums\Algorithm::RS384:
            case Enums\Algorithm::RS512:
                throw new Exceptions\NotSupportedException("Verifying a JWT with a secret is not supported on RSA keys");
        }
        throw new Exceptions\NotImplementedException();
    }

    /**
     * Undocumented function
     *
     * @param OpenSSLAsymmetricKey $key
     * @return boolean
     * @throws Exceptions\NotSupportedException
     */
    public function VerifyWithKey(OpenSSLAsymmetricKey $key): bool
    {
        switch ($this->header['alg'])
        {
            case Enums\Algorithm::HS256:
            case Enums\Algorithm::HS384:
            case Enums\Algorithm::HS512:
                throw new Exceptions\NotSupportedException("Verifying a JWT with a key is not supported on HMAC keys");
        }
        throw new Exceptions\NotImplementedException();
    }
}

/**
 * Undocumented class
 */
class JWT
{
    private array $header;
    private array $payload;
    private Enums\Algorithm $algorithm;

    /**
     * Undocumented function
     *
     * @param array|string $header
     * @param array|string $payload
     * @param Enums\Algorithm $algorithm
     * @throws Exceptions\NotImplementedException
     */
    function __construct(array|string $payload, Enums\Algorithm $algorithm)
    {
        $this->header = array('typ' => 'jwt', 'alg' => $algorithm);
        switch (gettype($payload))
        {
            case 'string':
                $this->payload = JWTElements::Base64ToArray($payload);
                break;
            case 'array':
                $this->payload = $payload;
                break;
        }
        $this->algorithm = $algorithm;

        switch ($algorithm)
        {
            case Enums\Algorithm::RS256:
            case Enums\Algorithm::RS384:
            case Enums\Algorithm::RS512:
                throw new Exceptions\NotImplementedException();
        }
    }

    /**
     * Undocumented function
     *
     * @param string $encodedJWT
     * @return JWTElements
     * @throws Exceptions\InvalidJWT
     */
    static function Decode(string $encodedJWT): JWTElements
    {
        $elements = explode('.', $encodedJWT);
        if(count($elements) !== 3)
        {
            throw new Exceptions\InvalidJWT('The provided string did not have 3 seperate elements');
        }

        $decodedHeader = JWTElements::Base64ToArray($elements[0]);
        $decodedPayload = JWTElements::Base64ToArray($elements[1]);
        if($decodedHeader === null || $decodedPayload === null)
        {
            throw new Exceptions\InvalidJWT('The provided JWT did not decode to valid JSON');
        }

        return new JWTElements($decodedHeader, $decodedPayload, $elements[2]);
    }

    /**
     * Undocumented function
     *
     * @param string $secret
     * @return string
     * @throws Exceptions\NotSupportedException
     */
    public function SignWithSecret(string $secret): string
    {
        switch ($this->algorithm)
        {
            case Enums\Algorithm::RS256:
            case Enums\Algorithm::RS384:
            case Enums\Algorithm::RS512:
                throw new Exceptions\NotSupportedException("Signing with a secret is not supported on RSA keys");
        }
        throw new Exceptions\NotImplementedException();
    }

    /**
     * Undocumented function
     *
     * @param OpenSSLAsymmetricKey $key
     * @return string
     * @throws Exceptions\NotSupportedException
     */
    public function SignWithKey(OpenSSLAsymmetricKey $key): string
    {
        switch ($this->algorithm)
        {
            case Enums\Algorithm::HS256:
            case Enums\Algorithm::HS384:
            case Enums\Algorithm::HS512:
                throw new Exceptions\NotSupportedException("Signing with a key is not supported on HMAC keys");
        }
        throw new Exceptions\NotImplementedException();
    }
}
?>