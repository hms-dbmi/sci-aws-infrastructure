#!/usr/bin/env bash

ONETIME_TOKEN=$(vault token-create -policy="sci-authz-dev-read" -use-limit=9 -ttl="1m" -format="json" | jq -r .auth.client_token)

aws ecs run-task    --cluster SCI-DEV \
                    --task-definition SCI-DEV-SCIAUTHZ \
                    --profile 68 \
                    --overrides "{\"containerOverrides\":[{\"name\":\"SCI-DEV_SCIAUTHZ\",\"environment\": [{\"name\":\"ONETIME_TOKEN\",\"value\": \"$ONETIME_TOKEN\"}]}]}"

ONETIME_TOKEN=$(vault token-create -policy="sci-auth-dev-read" -use-limit=12 -ttl="1m" -format="json" | jq -r .auth.client_token)

aws ecs run-task    --cluster SCI-DEV \
                    --task-definition SCI-DEV-SCIAUTH \
                    --profile 68 \
                    --overrides "{\"containerOverrides\":[{\"name\":\"SCI-DEV_SCIAUTH\",\"environment\": [{\"name\":\"ONETIME_TOKEN\",\"value\": \"$ONETIME_TOKEN\"}]}]}"

ONETIME_TOKEN=$(vault token-create -policy="scireg-dev-read" -use-limit=12 -ttl="1m" -format="json" | jq -r .auth.client_token)

aws ecs run-task    --cluster SCI-DEV \
                    --task-definition SCI-DEV-SCIREG \
                    --profile 68 \
                    --overrides "{\"containerOverrides\":[{\"name\":\"SCI-DEV_SCIREG\",\"environment\": [{\"name\":\"ONETIME_TOKEN\",\"value\": \"$ONETIME_TOKEN\"}]}]}"