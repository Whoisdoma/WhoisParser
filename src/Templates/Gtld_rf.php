<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Gtld_rf extends Regex
{

    /**
     * Blocks within the raw output of the whois
     * 
     * @var array
     * @access protected
     */
    protected $blocks = array(
            1 => '/domain:(.*?)(?=source)/is'
    );

    /**
     * Items for each block
     * 
     * @var array
     * @access protected
     */
    protected $blockItems = array(
            1 => array(
                    '/^paid-till:(.+)$/im' => 'expires'
            )
    );

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
        
        $date = \DateTime::createFromFormat('Y.m.d', trim($ResultSet->expires));
        $ResultSet->expires = $date->format('Y-m-d 00:00:00');
    }
}