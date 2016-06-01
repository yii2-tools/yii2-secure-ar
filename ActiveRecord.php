<?php

/**
 * Author: Pavel Petrov <itnelo@gmail.com>
 * Date: 24.04.16 5:59
 */

namespace yii\tools\secure;

use Yii;
use yii\tools\components\ActiveRecord as BaseActiveRecord;
use yii\tools\secure\behaviors\SecureBehavior;

class ActiveRecord extends BaseActiveRecord
{
    /**
     * If false, all queries to secure entities lose secure status
     * (secure filtering will not perform)
     * @var bool
     */
    private static $globalSecure = true;

    /**
     * @return array
     */
    public static function secureRoles()
    {
        return [];
    }

    /**
     * @return string
     */
    public static function secureAttribute()
    {
        return 'rbac_on';
    }

    /**
     * @return string
     */
    public static function secureItemAttribute()
    {
        return 'rbac_item';
    }

    /**
     * @return string
     */
    public static function secureItemTemplate()
    {
        return null;
    }

    /**
     * @return string
     */
    public static function queryClassName()
    {
        return ActiveQuery::className();
    }

    /**
     * @return bool
     */
    public static function isSecure()
    {
        return static::$globalSecure;
    }

    /**
     * @param bool $secure
     */
    public static function secure($secure)
    {
        static::$globalSecure = $secure;
    }

    /**
     * @inheritdoc
     */
    public function behaviors()
    {
        return array_merge(parent::behaviors(), [
            'secure' => [
                'class' => SecureBehavior::className(),
                'secureRoles' => static::secureRoles(),
                'secureAttribute' => static::secureAttribute(),
                'secureItemAttribute' => static::secureItemAttribute(),
                'secureItemTemplate' => static::secureItemTemplate(),
            ]
        ]);
    }

    /**
     * @inheritdoc
     * @return ActiveQuery the newly created [[ActiveQuery]] instance.
     */
    public static function find()
    {
        return Yii::createObject(
            [
                'class' => static::queryClassName(),
                'secureAttribute' => static::secureAttribute(),
                'secureItemAttribute' => static::secureItemAttribute(),
            ],
            [get_called_class()]
        );
    }
}
