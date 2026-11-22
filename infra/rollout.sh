#!/usr/bin/env bash
# Rolling deploy of an image tag to every running CyberDesk instance via SSM Run Command.
# Usage: infra/rollout.sh <image-tag>     (needs AWS_REGION; called by .github/workflows/deploy.yml)
# One instance at a time (--max-concurrency 1) so the ALB always has a healthy target;
# any failure stops the rollout (--max-errors 0) and fails the pipeline.
set -euo pipefail

TAG="${1:?usage: rollout.sh <image-tag>}"
[[ "$TAG" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid tag: $TAG"; exit 1; }
REGION="${AWS_REGION:?AWS_REGION not set}"

mapfile -t IDS < <(aws ec2 describe-instances --region "$REGION" \
  --filters Name=tag:Project,Values=CyberDesk Name=instance-state-name,Values=running \
  --query 'Reservations[].Instances[].InstanceId' --output text | tr '\t' '\n' | sed '/^$/d')
if [ "${#IDS[@]}" -eq 0 ]; then
  echo "::error::No running CyberDesk instances - is the CyberDesk stack deployed?"; exit 1
fi
echo "Instances: ${IDS[*]}"

echo "Waiting for the SSM agent on all instances (fresh instances need a few minutes)..."
for _ in $(seq 1 60); do
  online=$(aws ssm describe-instance-information --region "$REGION" \
    --filters "Key=InstanceIds,Values=$(IFS=,; echo "${IDS[*]}")" \
    --query "length(InstanceInformationList[?PingStatus=='Online'])" --output text)
  [ "$online" -eq "${#IDS[@]}" ] && break
  sleep 10
done
[ "$online" -eq "${#IDS[@]}" ] || { echo "::error::Only $online/${#IDS[@]} instances reachable via SSM"; exit 1; }

# cloud-init status --wait: a brand-new instance may still be installing Docker from UserData.
COMMANDS="[\"cloud-init status --wait >/dev/null || true\",\"/usr/local/bin/cyberdesk-deploy.sh $TAG\"]"
CMD_ID=$(aws ssm send-command --region "$REGION" \
  --document-name AWS-RunShellScript \
  --instance-ids "${IDS[@]}" \
  --max-concurrency 1 --max-errors 0 \
  --timeout-seconds 900 \
  --comment "CyberDesk deploy $TAG" \
  --parameters "{\"commands\":$COMMANDS,\"executionTimeout\":[\"900\"]}" \
  --query Command.CommandId --output text)
echo "SSM command: $CMD_ID"

for _ in $(seq 1 120); do
  sleep 10
  mapfile -t STATES < <(aws ssm list-command-invocations --region "$REGION" --command-id "$CMD_ID" \
    --query 'CommandInvocations[].[InstanceId,Status]' --output text)
  echo "${STATES[*]:-pending}"
  pending=0; failed=0
  for line in "${STATES[@]}"; do
    case "${line##*[[:space:]]}" in
      Success) ;;
      Pending|InProgress|Delayed) pending=1 ;;
      *) failed=1 ;;
    esac
  done
  if [ "${#STATES[@]}" -lt "${#IDS[@]}" ]; then pending=1; fi
  if [ "$failed" -eq 1 ] || [ "$pending" -eq 0 ]; then break; fi
done

aws ssm list-command-invocations --region "$REGION" --command-id "$CMD_ID" --details \
  --query 'CommandInvocations[].{instance:InstanceId,status:Status,output:CommandPlugins[0].Output}' --output text || true
[ "$failed" -eq 0 ] && [ "$pending" -eq 0 ] || { echo "::error::Rollout of $TAG failed"; exit 1; }
echo "Rollout of $TAG finished on ${#IDS[@]} instance(s)."
