-- name: GetVPNPublicKey :one
select value
from platform_settings
where type = 'vpn'
  and key = 'public_key';

-- name: GetVPNPrivateKey :one
select value
from platform_settings
where type = 'vpn'
  and key = 'private_key';

-- name: SetVPNPublicKey :exec
insert into platform_settings (type, key, value)
values ('vpn', 'public_key', $1);

-- name: SetVPNPrivateKey :exec
insert into platform_settings (type, key, value)
values ('vpn', 'private_key', $1);