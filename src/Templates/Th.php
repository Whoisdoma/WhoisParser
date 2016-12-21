<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Th extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=Tech Contact)/is', 
            2 => '/Tech Contact(?>[\x20\t]*):(?>[\x20\t]*)(.*?)\n\n/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Registrar(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/Name Server(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/Status(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/Updated date(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/Created date(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/Exp date(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/Domain Holder(?>[\x20\t]*):(?>[\x20\t]*)(.+)\n\n/is' => 'contacts:owner:name'), 
            2 => array(
                    '/Tech Contact(?>[\x20\t]*):(?>[\x20\t]*)(.+)\n\n/is' => 'contacts:tech:name'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No match for/i';

    /**
     * After parsing do something
     *
     * Fix address
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if (isset($ResultSet->contacts->owner[0]->name)) {
            $filteredAddress = array_map('trim', explode("\n", trim($ResultSet->contacts->owner[0]->name)));
            
            if (sizeof($filteredAddress) === 4) {
                $ResultSet->contacts->owner[0]->name = $filteredAddress[0];
                $ResultSet->contacts->owner[0]->address = $filteredAddress[1];
                $ResultSet->contacts->owner[0]->zipcode = $filteredAddress[2];
                $ResultSet->contacts->owner[0]->country = $filteredAddress[3];
            } else {
                $ResultSet->contacts->owner[0]->name = $filteredAddress[0];
                $ResultSet->contacts->owner[0]->address = array($filteredAddress[1], 
                        $filteredAddress[2]);
                $ResultSet->contacts->owner[0]->city = $filteredAddress[3];
                $ResultSet->contacts->owner[0]->zipcode = $filteredAddress[4];
                $ResultSet->contacts->owner[0]->country = $filteredAddress[5];
            }
        }
        
        if (isset($ResultSet->contacts->tech[0]->name)) {
            $filteredAddress = array_map('trim', explode("\n", trim($ResultSet->contacts->tech[0]->name)));
            
            $ResultSet->contacts->tech[0]->handle = $filteredAddress[0];
            $ResultSet->contacts->tech[0]->name = $filteredAddress[1];
            $ResultSet->contacts->tech[0]->address = $filteredAddress[2];
            $ResultSet->contacts->tech[0]->zipcode = $filteredAddress[3];
            $ResultSet->contacts->tech[0]->country = $filteredAddress[4];
        }
    }
}