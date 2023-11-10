#!/bin/sh

export VAULT_ADDR=http://localhost:8200

vault server -config=/vault/config/config.hcl &

sleep 3
vault operator unseal 1suKXvTDbE3fg+B+NnZicFpXEWGHemSOj1oQJl9eSkk=

wait
