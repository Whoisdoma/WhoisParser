<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

/**
 * Template for Verisign
 *
 * @category   Whoisdoma
 * @package    WhoisParser
 */
class Verisign extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain name:(?>[\x20\t]*)(.*?)(?=>>>)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/whois server:(?>[\x20\t]*)(.+)$/im' => 'whoisserver', 
                    '/registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/registrar iana id:(?>[\x20\t]*)(.+)$/im' => 'registrar:id', 
                    '/referral url:(?>[\x20\t]*)(.+)$/im' => 'registrar:url', 
                    '/creation date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/registry expiry date:(?>[\x20\t]*)(.+)$/im' => 'expires',
                    '/updated date:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/name server:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/dnssec:(?>[\x20\t]*)(.+)$/im' => 'dnssec', 
                    '/status:(?>[\x20\t]*)(.+)$/im' => 'status'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No match for/i';

    /**
     * After parsing ...
     * 
     * Verisign is a thin registry, therefore they only provide us some details and the
     * real whois server of the registrar for the given domain name. Therefore we have
     * to restart the process with the real whois server.
     * 
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $Config = $WhoisParser->getConfig();
        
        if ((isset($ResultSet->dnssec) || $ResultSet->dnssec === null) &&
                 ($ResultSet->dnssec === 'Unsigned delegation' || $ResultSet->dnssec == '')) {
            $ResultSet->dnssec = false;
        } else {
            $ResultSet->dnssec = true;
        }
        
        // check if registrar name is set, if not then there was an error while
        // parsing
        if (! isset($ResultSet->registrar->name)) {
            return;
        }
        
        $newConfig = $Config->get($ResultSet->whoisserver);

        if ($newConfig['server'] == '') {
            $newConfig['server'] = $ResultSet->whoisserver;
        }
        if ($newConfig['server'] == 'whois.iana.org') {
            $newConfig = null;
        }

        if (is_array($newConfig) && strlen($newConfig['server'])) {
            $Config->setCurrent($newConfig);
            $WhoisParser->call();
        }
    }
}