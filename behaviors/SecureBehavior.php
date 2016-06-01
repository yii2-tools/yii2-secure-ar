<?php

/**
 * Author: Pavel Petrov <itnelo@gmail.com>
 * Date: 24.04.16 4:20
 */

namespace yii\tools\secure\behaviors;

use Yii;
use yii\behaviors\BlameableBehavior;
use yii\helpers\ArrayHelper;
use yii\helpers\Inflector;
use yii\helpers\VarDumper;
use yii\base\InvalidConfigException;
use yii\base\Behavior;
use yii\db\BaseActiveRecord;
use yii\web\ForbiddenHttpException;
use yii\web\User;
use yii\widgets\ActiveForm;
use yii\tools\secure\ActiveRecord;

/**
 * Behavior suited for using with SecureActiveRecord.
 *
 * ATTENTION!
 * 1. This behavior will use only 1 primary key from composite key as route param.
 * 2. Owner class should be with declared transactions() with OP_ALL flags for all scenarios.
 * 3. Owner's cache dependencies should conside additional param - rbac manager cache criteria
 *      (it means if secure params of owner has changed – need to FORCE invalidate owner's cache)
 *
 * Performs management of secure auth item for concrete entity instance.
 * @package app\behaviors
 */
class SecureBehavior extends Behavior
{
    /**
     * @var ActiveRecord
     */
    public $owner;

    /**
     * Roles which user should have to change secure fields.
     * @var array
     */
    public $secureRoles = [];

    /**
     * Secure field name, should be present by $owner,
     * Values of field with this name:
     * 1 - means secure system enabled for this instance, 0 - disabled
     * @var string
     */
    public $secureAttribute = 'rbac_on';

    /**
     * Secure field name, should be present by $owner,
     * Represents name of the auth item for access to $owner
     * @var string
     */
    public $secureItemAttribute = 'rbac_item';

    /**
     * e.g. 'Access to page "{secureItemDescriptionParam}"', where:
     * {secureItemDescriptionParam} - will be replaced by real value of $secureItemDescriptionParam for concrete object.
     * @var string
     */
    public $secureItemDescription;

    /**
     * e.g. "My page title".
     * If not specified, real value of $routeParam will be used.
     * @var string
     */
    public $secureItemDescriptionParam;

    /**
     * Template for role name (for initial create operation).
     * @var string
     */
    public $secureItemTemplate;

    /**
     * Warning! For internal using.
     * @var array
     */
    public $secureAccessRoles;

    /**
     * Warning! For internal using.
     * @var string
     */
    public $secureAccessRolesAttribute = 'secureAccessRoles';

    /**
     * @var array
     */
    private $secureAttributesChanged = [];

    /**
     * @var string[]
     */
    private $currentSecureAccessRoles;

    /**
     * For internal purposes.
     * @var array
     */
    private $conflictsData;

    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();

        if (!isset($this->secureItemDescription)) {
            throw new InvalidConfigException("Property 'secureItemDescription' must be set");
        }

        if (!isset($this->secureItemDescriptionParam)) {
            $this->secureItemDescriptionParam = $this->secureItemAttribute;
        }
    }

    /**
     * @inheritdoc
     */
    public function events()
    {
        return array_merge(
            parent::events(),
            [
                BaseActiveRecord::EVENT_BEFORE_VALIDATE => 'resolveSecureAttributesChanged',

                BaseActiveRecord::EVENT_BEFORE_INSERT => 'resolveConflicts',

                BaseActiveRecord::EVENT_AFTER_INSERT => 'createSecureItem',
                BaseActiveRecord::EVENT_AFTER_UPDATE => 'updateSecureItem',
                BaseActiveRecord::EVENT_AFTER_DELETE => 'deleteSecureItem',
            ]
        );
    }

    /**
     * Resolve conflicts between behaviors.
     */
    public function resolveConflicts()
    {
        $this->preventConflicts();
    }

    /**
     * Performs conflicts resolving actions.
     * @param bool $rollback when performed action should be cancelled (state restoring)
     * @SuppressWarnings(PHPMD.ElseExpression)
     */
    public function preventConflicts($rollback = false)
    {
        // Fix: ignore `updated_by` during all update operations while $owner's INSERT event in process.
        if (($blameable = $this->owner->getBehavior('blameable')) instanceof BlameableBehavior) {
            Yii::info('Secure behavior conflict with blameable behavior resolving (rollback = '
                . VarDumper::dumpAsString($rollback) . ')', __METHOD__);

            if ($rollback) {
                $blameable->attributes[BaseActiveRecord::EVENT_BEFORE_UPDATE] =
                    $this->conflictsData['blameable']['attributes'][BaseActiveRecord::EVENT_BEFORE_UPDATE];
            } else {
                $this->conflictsData['blameable']['attributes'][BaseActiveRecord::EVENT_BEFORE_UPDATE] =
                    $blameable->attributes[BaseActiveRecord::EVENT_BEFORE_UPDATE];
                $blameable->attributes[BaseActiveRecord::EVENT_BEFORE_UPDATE] = [];
            }
        }
    }

    /**
     * @return string
     */
    public function createSecureItemName()
    {
        if (!($template = $this->secureItemTemplate)) {
            $uniquePart = strtoupper(Inflector::tableize((new \ReflectionClass($this->owner))->getShortName()));
            $template = 'ACCESS_' . $uniquePart;
        }

        $primaryKeys = $this->owner->getPrimaryKey(true);
        foreach ($primaryKeys as $value) {
            $template .= '_' . $value;
        }

        return $template;
    }

    /**
     * Returns true if $user can edit secure options for concrete entity ($owner).
     * @param User $user
     * @return bool
     */
    public function checkSecureAccess(User $user)
    {
        Yii::trace("Checking secure access to '{$this->owner->className()}'"
            . PHP_EOL . 'Identifier: ' . VarDumper::dumpAsString($this->owner->getPrimaryKey(true))
            . PHP_EOL . "User: {$user->getId()}", __METHOD__);

        if (($identity = $user->getIdentity()) && $identity->isAdmin) {
            return true;
        }

        if (empty($this->secureRoles)) {
            return false;
        }

        foreach ($this->secureRoles as $item) {
            if (!$user->can($item)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param ActiveForm $form
     * @return \yii\widgets\ActiveField
     */
    public function renderSecureAttributeField(ActiveForm $form)
    {
        if (!$this->checkSecureAccess($this->getUser())) {
            return;
        }

        $js = <<<JAVASCRIPT
            $(document).on('change', '.secure-{$this->secureAttribute}', function (event) {
                var secureItemField = $('.secure-{$this->secureAccessRolesAttribute}');
                var secureItemHintField = $('.secure-hint-{$this->secureAccessRolesAttribute}');
                secureItemField.prop('disabled', !secureItemField.prop('disabled'));
                secureItemHintField.toggle();
            });
JAVASCRIPT;

        $this->getView()->registerJs($js);

        return $form->field($this->owner, $this->secureAttribute)
            ->checkbox(['class' => 'secure-' . $this->secureAttribute]);
    }

    /**
     * @param ActiveForm $form
     * @return \yii\widgets\ActiveField
     */
    public function renderSecureAccessRolesField(ActiveForm $form)
    {
        if (!$this->checkSecureAccess($this->getUser())) {
            return;
        }

        $items = ArrayHelper::map($this->getAuthManager()->getRoles(), 'name', 'name');
        $secureOn = 1 === intval($this->owner->getAttribute($this->secureAttribute));
        if (!isset($this->secureAccessRoles)) {
            $this->secureAccessRoles = $this->resolveCurrentSecureAccessRoles();
        }

        $field = $form->field($this->owner, $this->secureAccessRolesAttribute)
            ->label(Yii::t('yii2-secure-ar', 'Roles'))
            ->dropDownList(
                $items,
                [
                    'class' => 'form-control secure-' . $this->secureAccessRolesAttribute,
                    'multiple' => true,
                    'size' => 8,
                    'disabled' => !$secureOn,
                ]
            );

        if (!$this->owner->isNewRecord) {
            $secureItemName = $this->owner->getAttribute($this->secureItemAttribute);

            $field->hint(
                '* ' . Yii::t(
                    'yii2-secure-ar',
                    'For granting access to an individual user, use the privilege "{0}"',
                    [$secureItemName]
                ),
                [
                    'class' => 'help-block secure-hint-' . $this->secureAccessRolesAttribute,
                    'style' => 'display: ' . ($secureOn ? 'block' : 'none') . ';',
                ]
            );
        }

        return $field;
    }

    public function createSecureItem()
    {
        if (!$this->owner->isTransactional(ActiveRecord::OP_INSERT)) {
            throw new \LogicException("Operation INSERT should be transactional for owner");
        }

        if (!$this->owner->{$this->secureItemAttribute}) {
            $this->owner->{$this->secureItemAttribute} = $this->createSecureItemName();
        }

        $authManager = $this->getAuthManager();
        $secureItem = $authManager->createPermission($this->owner->{$this->secureItemAttribute});
        $secureItem->active = $this->owner->{$this->secureAttribute} ? 1 : 0;
        $secureItem->description = Yii::t(
            'app',
            $this->secureItemDescription,
            ['secureItemDescriptionParam' => $this->owner->getAttribute($this->secureItemDescriptionParam)]
        );

        if (!$authManager->add($secureItem) || !$this->owner->save(false)) {
            throw new \Exception('Unexpected error during auth item creation for owner');
        }

        $this->reassignSecureItemForRoles($secureItem);
        $this->preventConflicts(true);
    }

    public function updateSecureItem()
    {
        if (!$this->owner->isTransactional(ActiveRecord::OP_UPDATE)) {
            throw new \LogicException("Operation UPDATE should be transactional for owner");
        }

        if (in_array(true, $this->secureAttributesChanged)) {
            $authManager = $this->getAuthManager();
            $oldName = $this->owner->getOldAttribute($this->secureItemAttribute);

            if ($secureItem = $authManager->getPermission($oldName)) {
                $secureItem->active = $this->owner->{$this->secureAttribute} ? 1 : 0;
                $secureItem->name = $this->owner->{$this->secureItemAttribute};

                if (!$authManager->update($oldName, $secureItem)) {
                    throw new \Exception('Unexpected error during auth item updating for owner');
                }

                $this->reassignSecureItemForRoles($secureItem);
            }
        }
    }

    public function deleteSecureItem()
    {
        if (!$this->owner->isTransactional(ActiveRecord::OP_DELETE)) {
            throw new \LogicException("Operation DELETE should be transactional for owner");
        }

        $authManager = $this->getAuthManager();

        if ($secureItem = $authManager->getPermission($this->owner->{$this->secureItemAttribute})) {
            if (!$authManager->remove($secureItem)) {
                throw new \Exception('Unexpected error during auth item removing for owner');
            }
        }
    }

    public function reassignSecureItemForRoles($item)
    {
        $authManager = $this->getAuthManager();
        $items = $authManager->getRoles();
        $currentAccessRoles = $this->resolveSecureAccessRoles();

        foreach ($items as $role) {
            $isChild = $authManager->hasChild($role, $item);
            $inScope = in_array($role->name, $currentAccessRoles);

            if (!$isChild && $inScope) {
                $authManager->addChild($role, $item);
            } elseif ($isChild && !$inScope) {
                $authManager->removeChild($role, $item);
            }
        }
    }

    /**
     * @return User
     */
    protected function getUser()
    {
        return Yii::$app->getUser();
    }

    /**
     * @return \yii\db\Connection
     */
    protected function getDb()
    {
        return $this->owner->getDb();
    }

    protected function getView()
    {
        return Yii::$app->controller->getView();
    }

    /**
     * @return \yii\rbac\ManagerInterface
     */
    protected function getAuthManager()
    {
        return Yii::$app->getAuthManager();
    }

    /**
     * @throws \yii\web\ForbiddenHttpException
     */
    protected function ensureSecureAccess()
    {
        $user = $this->getUser();

        if (!$this->checkSecureAccess($user)) {
            Yii::warning('Secure access check to concrete entity failed for user'
                . PHP_EOL . 'Secure roles: ' . VarDumper::dumpAsString($this->secureRoles)
                . PHP_EOL . 'Entity: ' . VarDumper::dumpAsString($this->owner, 2)
                . PHP_EOL . 'User identity: ' . VarDumper::dumpAsString($user->getIdentity(), 2), __METHOD__);

            throw new ForbiddenHttpException(Yii::t('yii', 'You are not allowed to perform this action.'));
        }
    }

    /**
     * @return bool
     */
    protected function isSecureAccessRolesChanged()
    {
        $currentAccessRoles = $this->resolveCurrentSecureAccessRoles();
        $accessRoles = $this->resolveSecureAccessRoles();
        $diff = array_diff($currentAccessRoles, $accessRoles);

        return !empty($diff);
    }

    /**
     * @return string[]
     * @SuppressWarnings(PHPMD.ElseExpression)
     */
    protected function resolveCurrentSecureAccessRoles()
    {
        if (!isset($this->currentSecureAccessRoles)) {
            Yii::trace('Resolving current roles that can access secure object'
                . PHP_EOL . VarDumper::dumpAsString($this->owner, 2) . "'", __METHOD__);

            $this->currentSecureAccessRoles = [];

            if ($permissionName = $this->owner->getOldAttribute($this->secureItemAttribute)) {
                $authManager = $this->getAuthManager();

                if (!($permission = $authManager->getPermission($permissionName))) {
                    Yii::warning("Secure access permission '$permissionName' doesn't exists or inactive."
                        . ' Array of secure access roles will be empty!', __METHOD__);

                    return $this->currentSecureAccessRoles;
                }

                $items = $authManager->getRoles();

                foreach ($items as $role) {
                    if ($authManager->hasChild($role, $permission)) {
                        $this->currentSecureAccessRoles[] = $role->name;
                    }
                }
            }
        }

        return $this->currentSecureAccessRoles;
    }

    /**
     * @return array
     */
    protected function resolveSecureAccessRoles()
    {
        $form = Yii::$app->getRequest()->getBodyParam($this->owner->formName());
        $field = $this->secureAccessRolesAttribute;

        if (!empty($form) && isset($form[$field]) && !empty($form[$field])) {
            return $form[$field];
        }

        return [];
    }

    public function resolveSecureAttributesChanged()
    {
        $secureAttributeChanged = $this->owner->isNewRecord
            ? 0 !== intval($this->owner->getAttribute($this->secureAttribute))
            : $this->owner->isAttributeChanged($this->secureAttribute);
        $secureItemAttributeChanged = $this->owner->isAttributeChanged($this->secureItemAttribute);
        $secureAccessRolesChanged = $this->isSecureAccessRolesChanged();

        $this->secureAttributesChanged = [
            $secureAttributeChanged,
            $secureItemAttributeChanged,
            $secureAccessRolesChanged,
        ];

        Yii::info('Resolve secure attributes changed result: '
            . PHP_EOL . VarDumper::dumpAsString($this->secureAttributesChanged), __METHOD__);

        if ($secureAttributeChanged || $secureItemAttributeChanged) {
            $this->ensureSecureAccess();
        }
    }
}
