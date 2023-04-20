<?php

/*
 * This file is a driver for allowing DNS resolving through GoDaddy API.
 * The API documentation can be found here: https://developer.godaddy.com/doc/endpoint/domains
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AcmePhp\Core\Challenge\Dns;

use AcmePhp\Core\Challenge\MultipleChallengesSolverInterface;
use AcmePhp\Core\Exception\Protocol\ChallengeFailedException;
use AcmePhp\Core\Protocol\AuthorizationChallenge;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\NullLogger;
use Webmozart\Assert\Assert;
use \Psr\Http\Message\ResponseInterface;
use \AcmePhp\Core\Challenge\ConfigurableServiceInterface;


class GoDaddySolver implements MultipleChallengesSolverInterface, ConfigurableServiceInterface
{
    use LoggerAwareTrait;

    /**
     * @var DnsDataExtractor
     */
    private $extractor;


    /**
     * @var \GuzzleHttp\Client
     */
    private $m_httpClient;


    /**
     * The key that GoDaddy provide you for authenticating API requests
     * @var string
     */
    private $m_apiKey;


    /**
     * The "secret" that GoDaddy provide with the key for authenticating API requests.
     * @var string
     */
    private $m_apiSecret;


    public function __construct(DnsDataExtractor $extractor = null, \GuzzleHttp\Client $httpClient)
    {
        $this->extractor = $extractor ?: new DnsDataExtractor();
        $this->m_apiKey = ""; // this gets set later in the configure public method.
        $this->m_apiSecret = ""; // this gets set later in the configure public method.
        $this->m_httpClient = $httpClient;
        $this->logger = new NullLogger();
    }


    /**
     * Configure this service from the details in the config file
     * @param array $config - the array form of the YAML file.
     */
    public function configure(array $config)
    {
        Assert::keyExists($config, 'api_key', 'configure::$config expected an array with the key %s.');
        Assert::keyExists($config, 'api_secret', 'configure::$config expected an array with the key %s.');
        $this->m_apiKey = $config['api_key'];
        $this->m_apiSecret = $config['api_secret'];
    }


    /**
     * {@inheritdoc}
     */
    public function supports(AuthorizationChallenge $authorizationChallenge): bool
    {
        return 'dns-01' === $authorizationChallenge->getType();
    }


    /**
     * {@inheritdoc}
     */
    public function solve(AuthorizationChallenge $authorizationChallenge)
    {
        $this->solveAll([$authorizationChallenge]);
    }


    /**
     * {@inheritdoc}
     */
    public function solveAll(array $authorizationChallenges)
    {
        Assert::allIsInstanceOf($authorizationChallenges, AuthorizationChallenge::class);

        foreach ($authorizationChallenges as $authorizationChallenge)
        {
            /* @var $authorizationChallenge AuthorizationChallenge */
            $recordFqdn = "_acme-challenge." . $authorizationChallenge->getDomain();
            $recordValue = $this->extractor->getRecordValue($authorizationChallenge);;
            $this->addTxtRecord($recordFqdn, $recordValue);
        }
    }


    /**
     * {@inheritdoc}
     */
    public function cleanup(AuthorizationChallenge $authorizationChallenge)
    {
        $this->cleanupAll([$authorizationChallenge]);
    }


    /**
     * {@inheritdoc}
     */
    public function cleanupAll(array $authorizationChallenges)
    {
        Assert::allIsInstanceOf($authorizationChallenges, AuthorizationChallenge::class);

        foreach ($authorizationChallenges as $challenge)
        {
            $fqdn = "_acme-challenge." . $challenge->getDomain();
            $domain = $this->getDomainFromFQDN($fqdn);
            $name = $this->getSubdomainForFQDN($fqdn);
            $this->removeRecord($domain, $name);
        }
    }


    /**
     * Send a request to GoDaddy to get the details of an existing domain
     */
    private function getExistingDomain(string $domain)
    {
        $domain = $this->getDomainFromFQDN($domain); // ensure no hostname.
        return $this->m_httpClient->request("GET", "/domains/{$domain}/records");
    }


    /**
     * Helper function that sends a request to the D.O. API, adding the necessary auth token.
     * @param string $method - the method. E.g. "GET", "POST", "DELETE".
     * @param string $endpoint - The API endpoint. E.g. "/domains"
     * @return \Psr\Http\Message\ResponseInterface
     */
    private function sendRequest(string $method, string $endpoint, $options = array()) : ResponseInterface
    {
        if (isset($options['headers']))
        {
            $headersArray = $options['headers'];
            $headersArray['Authorization'] = "sso-key {$this->m_apiKey}:{$this->m_apiSecret}";
        }
        else
        {
            $options['headers'] = array(
                'Authorization' => "sso-key {$this->m_apiKey}:{$this->m_apiSecret}",
            );
        }

        // prevent guzzle from raising an exception when receive non 200 code, instead return the response.
        $options['http_errors'] = false;

        // if endpoint starts with / then remove it so we dont end up with // in the URL.
        if (str_starts_with($endpoint, "/"))
        {
            $endpoint = substr($endpoint,1);
        }

        $url = "https://api.godaddy.com/v1/{$endpoint}";
        return $this->m_httpClient->request($method, $url, $options);
    }


    /**
     * Remove a record by name and type.
     * @param string $domain
     * @param string $name
     * @return void
     */
    private function removeRecord(string $domain, string $name, string $type="TXT")
    {
        $response = $this->sendRequest("DELETE", "/domains/{$domain}/records/{$type}/{$name}");

        // check that the request was successful
        if ($response->getStatusCode() !== 204)
        {
            print "Failed to cleanup TXT challenge record." . PHP_EOL;
        }
    }


    /**
     * Add a TXT record using GoDaddy API
     * https://developer.godaddy.com/doc/endpoint/domains#/v1/recordAdd
     * @param string $name - the TXT record FQDN. E.g. "test.mydomin.org"
     * @param string $value - the value for the TXT record.
     * @return void - throw exception if anything goes wrong.
     */
    private function addTxtRecord(string $name, string $value) : void
    {
        $domain = $this->getDomainFromFQDN($name); // ensure no hostname.
        $recordName = $this->getSubdomainForFQDN($name);

        $options = [
            'json' => [
                [
                    'type' => "TXT",
                    'name' => $recordName,
                    'data' => $value,
                    'ttl' => 600
                ]
            ]
        ];

        $response = $this->sendRequest("PATCH", "/domains/{$domain}/records", $options);

        if ($response->getStatusCode() !== 200)
        {
            $responseBody = $response->getBody();
            $responseObject = json_decode($responseBody, true);

            if ($responseObject === null)
            {
                throw new \Exception("Received non-JSON response back from GoDaddy API.");
            }

            if ($response->getStatusCode() === 422 && $responseObject['code'] === "DUPLICATE_RECORD")
            {
                // record already exists, remove it first before retrying.
                $this->removeRecord($domain, $recordName);

                // send the request again.
                $response = $this->sendRequest("PATCH", "/domains/{$domain}/records", $options);
            }
            else
            {
                throw new \Exception("There was an issue adding the challenge TXT record to GoDaddy.");
            }
        }

        if ($response->getStatusCode() !== 200) //isset($responseObject['domain_record']))
        {
            // failed repsonse, probably a bad auth token.
            throw new \Exception("Request failed, please check that your API auth token is valid.");
        }
    }


    /**
     * Fetches the DOMAIN part of a fully qualified domain name.
     * E.g. given: my.site.mydomain.com, this would return "mydomain.com"
     * @param string $FQDN - the fully qualified domain name.
     * @return string - the subdomain part of the FQDN.
     */
    private function getDomainFromFQDN($FQDN) : string
    {
        $secondLevelDomainsRegex = '/\.asn\.au$|\.com\.au$|\.net\.au$|\.id\.au$|\.org\.au$|\.edu\.au$|\.gov\.au$|\.csiro\.au$|\.act\.au$|\.nsw\.au$|\.nt\.au$|\.qld\.au$|\.sa\.au$|\.tas\.au$|\.vic\.au$|\.wa\.au$|\.co\.at$|\.or\.at$|\.priv\.at$|\.ac\.at$|\.avocat\.fr$|\.aeroport\.fr$|\.veterinaire\.fr$|\.co\.hu$|\.film\.hu$|\.lakas\.hu$|\.ingatlan\.hu$|\.sport\.hu$|\.hotel\.hu$|\.ac\.nz$|\.co\.nz$|\.geek\.nz$|\.gen\.nz$|\.kiwi\.nz$|\.maori\.nz$|\.net\.nz$|\.org\.nz$|\.school\.nz$|\.cri\.nz$|\.govt\.nz$|\.health\.nz$|\.iwi\.nz$|\.mil\.nz$|\.parliament\.nz$|\.ac\.za$|\.gov\.za$|\.law\.za$|\.mil\.za$|\.nom\.za$|\.school\.za$|\.net\.za$|\.co\.uk$|\.org\.uk$|\.me\.uk$|\.ltd\.uk$|\.plc\.uk$|\.net\.uk$|\.sch\.uk$|\.ac\.uk$|\.gov\.uk$|\.mod\.uk$|\.mil\.uk$|\.nhs\.uk$|\.police\.uk$/';
        $parts = array_reverse(explode('.', $FQDN));

        if (preg_match($secondLevelDomainsRegex, $FQDN))
        {
            $domain = "$parts[2].$parts[1].$parts[0]";
        }
        else
        {
            $domain = "$parts[1].$parts[0]";
        }

        return $domain;
    }


    /**
     * Fetches the subdomain part of a fully qualified domain name.
     * E.g. given: my.site.mydomain.com, this would return "my.site"
     * @param string $FQDN - the fully qualified domain name.
     * @return string - the subdomain part of the FQDN.
     */
    private function getSubdomainForFQDN(string $FQDN) : string
    {
        $domain = $this->getDomainFromFQDN($FQDN);
        $numPartsInDomain = count(explode(".", $domain));

        $parts = explode(".", $FQDN);

        // remove the last two elements which are the domain.
        for ($i=0; $i<$numPartsInDomain; $i++)
        {
            array_pop($parts);
        }
        
        $subdomain = implode(".", $parts);
        return $subdomain;
    }
}
