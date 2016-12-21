<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Hk extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/Registrant Contact Information:(.*?)(?=Administrative|Technical Contact Information)/is', 
            2 => '/Administrative Contact Information:(?>[\x20\t]*)(.*?)(?=Technical Contact Information)/is', 
            3 => '/Technical Contact Information:(?>[\x20\t]*)(.*?)(?=Name Servers Information)/is', 
            4 => '/Name Servers Information:(?>[\x20\t]*)(.*?)(?=---)/is', 
            5 => '/Registrar Name:(?>[\x20\t]*)(.*?)(?=Registrant Contact Information)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array(
                    '/(Company|Holder) English Name(.*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/Address:(?>[\x20\t]*)(.+)(?=Country)/is' => 'contacts:owner:address', 
                    '/Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email', 
                    '/Domain Name Commencement Date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/Expiry Date:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            2 => array('/Given name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/Family name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/Company name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/Address:(?>[\x20\t]*)(.+)(?=Country)/is' => 'contacts:admin:address', 
                    '/Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email', 
                    '/Account Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle'), 
            3 => array('/Given name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/Family name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/Company name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/Address:(?>[\x20\t]*)(.+)(?=Country)/is' => 'contacts:tech:address', 
                    '/Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email', 
                    '/Account Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle'), 
            4 => array('/Name Servers Information:\n(?>[\x20\t]*)(.*?)$/is' => 'nameserver'), 
            5 => array('/Registrar Name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/Registrar Contact Information: Email:(?>[\x20\t]*)(.+)(?>[\x20\t]*)Hotline:/im' => 'registrar:email'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/The domain has not been registered./i';

    /**
     * After parsing ...
     *
     * Fix contact addresses and nameserver in WHOIS output
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->address = array_map('trim', explode("\n", trim($contactObject->address)));
            }
        }
        
        if ($ResultSet->nameserver != '') {
            $ResultSet->nameserver = array_map('trim', explode("\n", trim($ResultSet->nameserver)));
        }
    }
}