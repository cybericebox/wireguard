-- name: GetPlatformSettings :one
select value
from platform_settings
where key = $1;

-- name: CreatePlatformSettings :exec
insert into platform_settings (key, value)
values ($1, $2);

-- name: UpdatePlatformSettings :execrows
update platform_settings
set value = $2,
    updated_at = now()
where key = $1;
