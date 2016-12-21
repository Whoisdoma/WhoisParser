<?php

namespace Whoisdoma\WhoisParser\Result;


class Contact extends AbstractResult
{

    /**
	 * Handle name
	 * 
	 * @var string
	 * @access protected
	 */
    protected $handle;

    /**
     * Handle type
     *
     * @var string
     * @access protected
     */
    protected $type;

    /**
	 * Name of person
	 * 
	 * @var string
	 * @access protected
	 */
    protected $name;

    /**
	 * Name of organization
	 * 
	 * @var string
	 * @access protected
	 */
    protected $organization;

    /**
	 * Email address
	 * 
	 * @var string
	 * @access protected
	 */
    protected $email;

    /**
	 * Address field
	 * 
	 * @var array
	 * @access protected
	 */
    protected $address;

    /**
	 * Zipcode of address
	 * 
	 * @var string
	 * @access protected
	 */
    protected $zipcode;

    /**
	 * City of address
	 * 
	 * @var string
	 * @access protected
	 */
    protected $city;

    /**
	 * State of address
	 *
	 * @var string
	 * @access protected
	 */
    protected $state;

    /**
	 * Country of address
	 * 
	 * @var string
	 * @access protected
	 */
    protected $country;

    /**
	 * Phone number
	 * 
	 * @var string
	 * @access protected
	 */
    protected $phone;

    /**
	 * Fax number
	 * 
	 * @var string
	 * @access protected
	 */
    protected $fax;

    /**
	 * Created date of handle
	 * 
	 * @var string
	 * @access protected
	 */
    protected $created;

    /**
	 * Last changed date of handle
	 * 
	 * @var string
	 * @access protected
	 */
    protected $changed;
}
