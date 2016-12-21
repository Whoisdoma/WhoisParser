<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Cz extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*)(.*?)(?=nnset:|contact:)/is', 
            2 => '/nserver:(?>[\x20\t]*)(.*?)(?=nsset:|contact:|$)/is', 
            3 => '/contact:(?>[\x20\t]*)(.*?)(?=nsset:|contact:|$)/is', 
            4 => '/keyset:(?>[\x20\t]*)(.*?)(?=dnskey)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/registrant:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:owner', 
                    '/admin-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin', 
                    '/registered:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/expire:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/changed:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name'), 
            2 => array('/nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/nserver:(?>[\x20\t]*)(.+) \(.+\)$/im' => 'nameserver', 
                    '/nserver:(?>[\x20\t]*).+ \((.+)\)$/im' => 'ips', 
                    '/tech-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech'), 
            3 => array('/contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/org:(?>[\x20\t]*)(.+)$/im' => 'contacts:organization', 
                    '/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/created:(?>[\x20\t]*)(.+)$/im' => 'contacts:created', 
                    '/changed:(?>[\x20\t]*)(.+)$/im' => 'contacts:changed'), 
            4 => array('/keyset:(?>[\x20\t]*)(.+)$/im' => 'dnssec'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/no entries found/i';

    /**
     * After parsing ...
     * 
     * If dnssec key was found we set attribute to true. We are also
     * reassigning the contact address.
     * 
	 * @param  object &$WhoisParser
	 * @return void
	 */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if ($ResultSet->dnssec != '') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                switch (sizeof($contactObject->address)) {
                    case 4:
                        $contactObject->city = $contactObject->address[1];
                        $contactObject->zipcode = $contactObject->address[2];
                        $contactObject->country = $contactObject->address[3];
                        $contactObject->address = $contactObject->address[0];
                        break;
                    case 5:
                        $contactObject->city = $contactObject->address[1];
                        $contactObject->zipcode = $contactObject->address[2];
                        $contactObject->state = $contactObject->address[3];
                        $contactObject->country = $contactObject->address[4];
                        $contactObject->address = $contactObject->address[0];
                        break;
                }
            }
        }
    }
}