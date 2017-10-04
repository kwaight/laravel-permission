<?php

namespace Spatie\Permission\Models;

use Illuminate\Database\Eloquent\Model;
use Spatie\Permission\Exceptions\TenantDoesNotExist;
use Spatie\Permission\Traits\HasPermissions;
use Spatie\Permission\Contracts\Tenant as TenantContract;
use Spatie\Permission\Traits\RefreshesPermissionCache;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

class Tenant extends Model implements TenantContract
{
    use HasPermissions;
    use RefreshesPermissionCache;

    public $guarded = ['id'];

    public function __construct(array $attributes = [])
    {
        $attributes['guard_name'] = $attributes['guard_name'] ?? config('auth.defaults.guard');

        parent::__construct($attributes);

        $this->setTable(config('permission.table_names.tenants'));
    }

    public function roles(): BelongsToMany
    {
        return $this->belongsToMany(
            config('permission.models.role'),
            config('permission.table_names.role_tenant_user')
        );
    }

    /**
     * A role belongs to some users of the model associated with its guard.
     */
    public function users(): BelongsToMany
    {
        return $this->belongsToMany(
            'App\User',
            config('permission.table_names.role_tenant_user')
        );
    }

    /**
     * Find a tenant by its name.
     *
     * @param string $name
     *
     * @return \Spatie\Permission\Contracts\Tenant|\Spatie\Permission\Models\Tenant
     *
     * @throws \Spatie\Permission\Exceptions\TenantDoesNotExist
     */
    public static function findByName(string $name): TenantContract
    {
        $tenant = static::where(config('permission.table_columns.tenants.name'), $name)->first();

        if (! $tenant) {
            throw TenantDoesNotExist::create($name);
        }

        return $tenant;
    }
}
