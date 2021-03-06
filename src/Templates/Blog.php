<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

/**
 * Template for .Blog
 *
 * @category   Whoisdoma
 * @package    WhoisParser
 */
class Blog extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain name:(?>[\x20\t]*)(.*?)(?=registrar)/is',
        2 => '/registrar:(?>[\x20\t]*)(.*?)(?=registrant|name servers)/is',
        3 => '/registrant:(?>[\x20\t]*)(.*?)(?=administrative contact)/is',
        4 => '/administrative contact:(?>[\x20\t]*)(.*?)(?=technical contact)/is',
        5 => '/technical contact:(?>[\x20\t]*)(.*?)(?=name servers)/is',
        6 => '/name server:(?>[\x20\t]*)(.*?)(?=% whois)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
        1 => array('/domain status:(?>[\x20\t]*)(.+)$/im' => 'status',
            '/creation Date:(?>[\x20\t]*)(.+)$/im' => 'created',
            '/expiry Date:(?>[\x20\t]*)(.+)$/im' => 'expires',
            '/updated date:(?>[\x20\t]*)(.+)$/im' => 'changed'),
        2 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name',
            '/number:(?>[\x20\t]*)(.*)$/im' => 'registrar:id'),
        3 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name'),
        4 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name',
            '/postal address:(?>[\x20\t]*)(.+)(?=Phone)/is' => 'contacts:admin:address',
            '/email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email',
            '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone',
            '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax'),
        5 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name',
            '/postal address:(?>[\x20\t]*)(.+)(?=Phone)/is' => 'contacts:tech:address',
            '/email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email',
            '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone',
            '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax'),
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