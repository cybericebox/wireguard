-- name: GetVPNServerPublicKey :one
select value
from platform_settings
where type = 'vpn'
  and key = 'public_key';

-- name: GetVPNServerPrivateKey :one
select value
from platform_settings
where type = 'vpn'
  and key = 'private_key';

-- name: SetVPNServerPublicKey :exec
insert into platform_settings (type, key, value)
values ('vpn', 'public_key', $1);

-- name: SetVPNServerPrivateKey :exec
insert into platform_settings (type, key, value)
values ('vpn', 'private_key', $1);