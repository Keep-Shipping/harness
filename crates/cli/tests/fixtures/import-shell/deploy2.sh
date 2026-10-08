#!/usr/bin/env bash
# Ship the API: build the image, move the infrastructure, roll it out, warm the
# fleet. A realistic deploy script, of the kind people actually keep in a repo.
set -euo pipefail

REGION=eu-west-1
IMAGE=ghcr.io/acme/api
VERSION="${GITHUB_SHA:0:7}"

cd "$(dirname "$0")"

docker build -f Dockerfile -t "$IMAGE:$VERSION" ./api
docker push "$IMAGE:$VERSION"

# Smoke-test the image before anything depends on it.
docker run --rm "$IMAGE:$VERSION" /api/healthz

tofu plan -out=prod.tfplan -var="region=$REGION" ./infra/prod
tofu apply prod.tfplan

kubectl apply -f k8s/namespace.yaml
helm upgrade api ./chart --set image.tag="$VERSION" --namespace acme
kubectl set image deployment/api api="$IMAGE:$VERSION" -n acme
kubectl rollout status deployment/api -n acme

if [ "$REGION" = "eu-west-1" ]; then
  aws cloudfront create-invalidation --distribution-id "$CDN_ID" --paths "/*"
fi

for host in web-1 web-2 web-3; do
  ssh "$host" 'sudo systemctl restart api && sudo systemctl reload nginx'
done

echo "done: $IMAGE:$VERSION is live in $REGION"