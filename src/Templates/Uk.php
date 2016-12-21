<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

/**
 * Template for .UK
 *
 * @category   Whoisdoma
 * @package    WhoisParser
 */
class Uk extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/registrant:(.*?)(?=registrant type:)/is', 
            2 => '/address:(.*?)(?=registrar:)/is', 3 => '/registrar:(.*?)(?=relevant dates:)/is', 
            4 => '/relevant dates:(.*?)(?=registration status:)/is', 
            5 => '/registration status:(.*?)(?=name servers:)/is', 
            6 => '/name servers:(.*?)(?=whois lookup made)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/registrant:(?>[\n\x20\t]*)(.+)/im' => 'contacts:owner:name'), 
            2 => array('/address:(?>[\n\x20\t]*)(.+)$/is' => 'contacts:owner:address'), 
            3 => array('/registrar:(?>[\n\x20\t]*)(.+) \[.+\]$/im' => 'registrar:name', 
                    '/url:(?>[\n\x20\t]*)(.+)$/im' => 'registrar:url', 
                    '/\[tag = (.+)\]$/im' => 'registrar:id'), 
            4 => array('/registered on:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/expiry date:(?>[\x20\t]*)(.*)$/im' => 'expires', 
                    '/last updated:(?>[\x20\t]*)(.+)$/im' => 'changed'), 
            5 => array('/registration status:(?>[\n\x20\t]*)(.+)/im' => 'status'), 
            6 => array('/\n(?>[\x20\t]+)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/This domain name has not been registered/i';

    protected $rateLimit = '/^the WHOIS query quota for [^\s]+ has been exceeded$/im';

    /**
     * After parsing do something
     *
     * Fix owner address
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = array_map('trim', explode("\n", trim($contactObject->address)));
                
                $contactObject->address = $filteredAddress[0];
                $contactObject->city = $filteredAddress[1];
                $contactObject->state = $filteredAddress[2];
                $contactObject->zipcode = $filteredAddress[3];
                $contactObject->country = $filteredAddress[4];
            }
        }
    }
}