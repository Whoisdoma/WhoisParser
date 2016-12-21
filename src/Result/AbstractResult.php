<?php

namespace Whoisdoma\WhoisParser\Result;


abstract class AbstractResult
{

    /**
     * Writing data to properties
     *
     * @param  string $name
     * @param  mixed $value
     * @return void
     */
    public function __set($name, $value)
    {
        $this->{$name} = $value;
    }

    /**
     * Checking data
     *
     * @param  mixed $name
     * @return boolean
     */
    public function __isset($name)
    {
        return isset($this->{$name});
    }

    /**
     * Reading data from properties
     *
     * @param  string $name
     * @return mixed
     */
    public function __get($name)
    {
        if (isset($this->{$name})) {
            return $this->{$name};
        }
        
        return null;
    }


    public function addItem($key, $value, $append = false)
    {
        if ($value === null) {
            $this->$key = null;
            return;
        }
        if (is_string($value) && (strlen($value) < 1)) {
            return;
        }
        if (is_array($value) && (count($value) < 1)) {
            return;
        }

        if (! (isset($this->$key) && ($key !== null))) {
            $this->$key = $value;
            return;
        }

        if ($append) {
            if ($this->$key !== null) {
                if (!is_array($this->$key)) {
                    $this->$key = array($this->$key);
                }
                $this->{$key}[] = $value;
                return;
            }
        }

        $this->$key = $value;
    }


    /**
     * Convert properties to json
     *
     * @return string
     */
    public function toJson()
    {
        return json_encode($this->toArray());
    }

    /**
     * Convert properties to array
     *
     * @return array
     */
    public function toArray()
    {
        return get_object_vars($this);
    }
}
