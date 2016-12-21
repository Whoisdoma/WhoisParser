<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Kg extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/administrative contact:(?>[\x20\t]*)(.*?)(?=technical contact)/is', 
            2 => '/technical contact:(?>[\x20\t]*)(.*?)(?=billing contact)/is', 
            3 => '/billing contact:(?>[\x20\t]*)(.*?)(?=record created)/is', 
            4 => '/record created(?>[\x20\t]*)(.*?)(?=name servers in the listed order)/is', 
            5 => '/name servers in the listed order(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/pid:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle', 
                    '/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax'), 
            2 => array('/pid:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax'), 
            3 => array('/pid:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:handle', 
                    '/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/email:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:email', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:address', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:fax', 
                    '/domain support:(?>[\x20\t]*)(.+) \(.+\)$/im' => 'registrar:name'), 
            4 => array('/record created:(?>[\x20\t]*)(.*?)$/im' => 'created', 
                    '/record last updated on (?>[\x20\t]*)(.*?)$/im' => 'changed', 
                    '/record expires on (?>[\x20\t]*)(.*?)$/im' => 'expires'), 
            5 => array('/\n(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/\n(?>[\x20\t]*)(.+) .+$/im' => 'nameserver', 
                    '/\n(?>[\x20\t]*).+ (.+)$/im' => 'ips'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Data not found/i';

    /**
     * After parsing do something
     *
     * Fix UTF-8 encoding in contact handles
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->address = utf8_encode($contactObject->address);
                $contactObject->name = utf8_encode($contactObject->name);
            }
        }
    }
}