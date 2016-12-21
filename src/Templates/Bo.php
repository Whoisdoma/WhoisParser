<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Bo extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/titular:(?>[\x20\t]*)(.*?)(?=contacto administrativo)/is', 
            2 => '/contacto administrativo:(?>[\x20\t]*)(.*?)(?=contacto techino)/is', 
            3 => '/contacto techino:(?>[\x20\t]*)(.*?)(?=contacto financiero)/is', 
            4 => '/contacto financiero:(?>[\x20\t]*)(.*?)(?=Fecha de registro)/is', 
            5 => '/Fecha de registro:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Organizacion:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/Nombre:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/Direccion:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/Ciudad:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/Pais:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/Telefono:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            2 => array('/Organizacion:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/Nombre:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/Direccion:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/Ciudad:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/Pais:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/Telefono:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'), 
            3 => array('/Organizacion:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/Nombre:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/Direccion:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/Ciudad:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/Pais:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/Telefono:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            4 => array('/Organizacion:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:organization', 
                    '/Nombre:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/Direccion:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:address', 
                    '/Ciudad:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:city', 
                    '/Pais:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:country', 
                    '/Telefono:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:phone', 
                    '/Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:email'), 
            5 => array('/Fecha de registro:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/Fecha de vencimiento:(?>[\x20\t]*)(.+)$/im' => 'expires'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/^\n\n(whois\.nic\.bo).+$/is';

    /**
     * After parsing ...
     *
     * Fix email addresses in WHOIS output
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->email = str_replace(' en ', '@', $contactObject->email);
            }
        }
    }
}