<?php

/**
 * Author: Pavel Petrov <itnelo@gmail.com>
 * Date: 24.04.16 6:44
 */

namespace yii\tools\secure\behaviors;

use Yii;
use yii\helpers\VarDumper;
use yii\base\Behavior;
use yii\log\Logger;
use yii\web\User;
use yii\tools\interfaces\SecureActiveQueryInterface;
use yii\tools\events\PopulateEvent;
use yii\tools\secure\ActiveQuery;

/**
 * Behavior suited for using with SecureActiveQuery.
 *
 * Performs low level access checks logic for entities and removes
 * restricted instances from result set (on SELECT queries).
 * @package app\behaviors
 */
class SecureFilterBehavior extends Behavior
{
    /**
     * @var ActiveQuery
     */
    public $owner;

    /**
     * @var bool
     */
    public $enabled = true;

    /**
     * @inheritdoc
     */
    public function events()
    {
        return $this->enabled ? [ActiveQuery::EVENT_BEFORE_POPULATE => 'filterRows'] : [];
    }

    /**
     * @param PopulateEvent $event
     */
    public function filterRows(PopulateEvent $event)
    {
        if ($event->isSecure()) {
            $event->rows = $this->filterRowsInternal($event->rows, $event->query);
        }
    }

    /**
     * @param array $rows
     * @param SecureActiveQueryInterface $query
     * @return array rows remaining after filter applying
     */
    protected function filterRowsInternal(array $rows, SecureActiveQueryInterface $query)
    {
        Yii::trace('Secure access filtering starts'
            . PHP_EOL . 'Query: ' . VarDumper::dumpAsString($query, 2)
            . PHP_EOL . 'Rows: ' . VarDumper::dumpAsString($rows), __METHOD__);

        $resultRows = [];
        $reducedRows = [];

        foreach ($rows as $row) {
            if ($this->isFilterRequired($row, $query) && $this->filter($row, $query)) {
                $reducedRows[] = $row;

                continue;
            }
            $resultRows[] = $row;
        }

        Yii::info(
            'Secure access filtering result'
            . PHP_EOL . 'Rows remains: ' . VarDumper::dumpAsString($resultRows)
            . PHP_EOL . 'Result set reduced by: ' . VarDumper::dumpAsString(count($rows) - count($resultRows))
            . PHP_EOL . 'Rows reduced: ' . VarDumper::dumpAsString($reducedRows),
            __METHOD__
        );

        return $resultRows;
    }

    /**
     * @param array $row
     * @param SecureActiveQueryInterface $query
     * @return bool
     */
    protected function filter(array $row, SecureActiveQueryInterface $query)
    {
        return !$this->checkAccess($row, $query, $this->getUser());
    }

    /**
     * @return User
     */
    protected function getUser()
    {
        return Yii::$app->getUser();
    }

    /**
     * @param array $row
     * @param SecureActiveQueryInterface $query
     * @return bool
     * @throws \LogicException
     */
    protected function isFilterRequired(array $row, SecureActiveQueryInterface $query)
    {
        $secureField = $query->getSecureAttribute();

        if (!isset($row[$secureField])) {
            throw new \LogicException("Row from database should contain secure field '$secureField'");
        }

        return 1 === intval($row[$secureField]);
    }

    /**
     * @param array $row
     * @param SecureActiveQueryInterface $query
     * @param User $user
     * @return User
     * @throws \LogicException
     * @SuppressWarnings(PHPMD.ElseExpression)
     */
    protected function checkAccess(array $row, SecureActiveQueryInterface $query, User $user)
    {
        $identifier = ($identity = $user->getIdentity()) ? $identity->username : 0;
        Yii::trace("Checking access to row data for user '$identifier'"
            . PHP_EOL . VarDumper::dumpAsString($row), __METHOD__);

        $secureItemField = $query->getSecureItemAttribute();
        if (!isset($row[$secureItemField])) {
            throw new \LogicException("Row from database should contain secure item field '$secureItemField'");
        }
        $permission = $row[$secureItemField];

        if (!is_null($identity) && $identity->isAdmin) {
            $result = true;
        } else {
            $result = $user->can($permission);
        }

        Yii::getLogger()->log(
            ($result ? 'Access granted' : 'Access denied') . " for user '$identifier' (" . $permission . ')',
            $result ? Logger::LEVEL_INFO : Logger::LEVEL_WARNING,
            __METHOD__
        );

        return $result;
    }
}
