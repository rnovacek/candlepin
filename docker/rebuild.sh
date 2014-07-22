#!/bin/sh
#
# Rebuilds all docker containers from base on down, and pushes each to the internal registry.

REGISTRY="docker.usersys.redhat.com"
REGISTRY_USER="${REGISTRY_USER:-alikins}"


build_and_push () {
    TAG="$1"
    DIR=$2
    pushd $DIR
    IMAGE_URI="${REGISTRY}/${REGISTRY_USER}/${TAG}"
    echo docker build -t "${TAG}" .
    echo docker tag "${TAG}" "${IMAGE_URI}"
    echo docker push "${IMAGE_URI}"
    popd
}

build_and_push "candlepin-base" base
build_and_push "candlepin-postgresql" postgresql
#docker build -t candlepin-postgresql .
#docker tag candlepin-postgresql docker.usersys.redhat.com/dgoodwin/candlepin-postgresql
#docker push docker.usersys.redhat.com/dgoodwin/candlepin-postgresql
