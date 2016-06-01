<?php

/**
 * Author: Pavel Petrov <itnelo@gmail.com>
 * Date: 24.04.16 5:56
 */

namespace yii\tools\secure;

use Yii;
use yii\tools\interfaces\SecureActiveQueryInterface;
use yii\tools\components\ActiveQuery as BaseActiveQuery;
use yii\tools\secure\behaviors\SecureFilterBehavior;

class ActiveQuery extends BaseActiveQuery implements SecureActiveQueryInterface
{
    /**
     * @var bool
     */
    public $secureEnabled = true;

    /**
     * @var string
     */
    public $secureAttribute;

    /**
     * @var string
     */
    public $secureItemAttribute;

    /**
     * @var bool
     */
    private $secure = false;

    /**
     * @inheritdoc
     */
    public function behaviors()
    {
        return array_merge(parent::behaviors(), [
            'secureFilter' => [
                'class' => SecureFilterBehavior::className(),
                'enabled' => $this->isSecureEnabled(),
            ],
        ]);
    }

    /**
     * @inheritdoc
     */
    public function isSecureEnabled()
    {
        return ActiveRecord::isSecure() && $this->secureEnabled;
    }

    /**
     * @inheritdoc
     */
    public function isSecure()
    {
        return $this->secure;
    }

    /**
     * @inheritdoc
     */
    public function secure($secure)
    {
        $this->secure = $secure;

        return $this;
    }

    /**
     * @inheritdoc
     */
    public function getSecureAttribute()
    {
        return $this->secureAttribute;
    }

    /**
     * @inheritdoc
     */
    public function getSecureItemAttribute()
    {
        return $this->secureItemAttribute;
    }
}
