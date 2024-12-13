-- name: GetPlatformSettings :one
select value
from platform_settings
where key = $1;

-- name: UpdatePlatformSettings :execrows
update platform_settings
set value = $2,
    key   = $1;