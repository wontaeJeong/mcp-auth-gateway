#!/bin/sh
set -eu

die() {
	printf '%s\n' "$1" >&2
	exit 1
}

validate_ca_bundle() {
	awk '
		/^-----BEGIN CERTIFICATE-----$/ {
			if (in_certificate) exit 1
			in_certificate = 1
			saw_certificate = 1
			saw_data = 0
			next
		}
		/^-----END CERTIFICATE-----$/ {
			if (!in_certificate || !saw_data) exit 1
			in_certificate = 0
			next
		}
		in_certificate {
			if ($0 !~ /^[A-Za-z0-9+\/=[:space:]]+$/) exit 1
			if ($0 ~ /[^[:space:]]/) saw_data = 1
			next
		}
		$0 !~ /^[[:space:]]*$/ { exit 1 }
		END { if (!saw_certificate || in_certificate) exit 1 }
	' "$CA_CERT_FILE"
}

validate_inputs() {
	[ -n "${REGISTRY:-}" ] || die 'REGISTRY is required'
	case "$REGISTRY" in
		*[!A-Za-z0-9._:/-]*|*/) die 'REGISTRY is invalid' ;;
	esac

	[ -n "${IMAGE_TAG:-}" ] || die 'IMAGE_TAG is required'
	case "$IMAGE_TAG" in
		*[!0-9A-Fa-f]*) die 'IMAGE_TAG must be an immutable git SHA' ;;
	esac
	tag_length=${#IMAGE_TAG}
	if [ "$tag_length" -lt 7 ] || [ "$tag_length" -gt 64 ]; then
		die 'IMAGE_TAG must be an immutable git SHA'
	fi

	[ -n "${CA_CERT_FILE:-}" ] || die 'CA_CERT_FILE is required'
	[ -r "$CA_CERT_FILE" ] && [ -s "$CA_CERT_FILE" ] || die 'CA_CERT_FILE must be readable and non-empty'
	validate_ca_bundle || die 'CA_CERT_FILE must contain a PEM certificate bundle'

	PUSH=${PUSH:-0}
	case "$PUSH" in
		0|1) ;;
		*) die 'PUSH must be 0 or 1' ;;
	esac
}

validate_inputs

case "$CA_CERT_FILE" in
	/*) ;;
	*)
		ca_directory=${CA_CERT_FILE%/*}
		ca_basename=${CA_CERT_FILE##*/}
		if [ "$ca_directory" = "$CA_CERT_FILE" ]; then
			ca_directory=.
		fi
		ca_directory=$(CDPATH= cd -- "$ca_directory" && pwd -P) || die 'could not resolve CA_CERT_FILE'
		CA_CERT_FILE=$ca_directory/$ca_basename
		;;
esac

if ! DOCKER_BUILDKIT=1 docker build --help 2>&1 | grep -Eq -- '(^|[[:space:]])--secret([=[:space:]]|$)'; then
	die 'docker build does not support required BuildKit secrets'
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
repository=$REGISTRY/mcp-platform/mcp-auth-gateway
image=$repository:$IMAGE_TAG

build_HTTP_PROXY=${HTTP_PROXY:-${PROXY:-}}
build_HTTPS_PROXY=${HTTPS_PROXY:-${PROXY:-}}
build_NO_PROXY=${NO_PROXY:-}
build_ALL_PROXY=${ALL_PROXY:-${PROXY:-}}
build_http_proxy=${http_proxy:-${PROXY:-}}
build_https_proxy=${https_proxy:-${PROXY:-}}
build_no_proxy=${no_proxy:-}
build_all_proxy=${all_proxy:-${PROXY:-}}

(
	cd "$repo_root"
	DOCKER_BUILDKIT=1 \
	HTTP_PROXY="$build_HTTP_PROXY" \
	HTTPS_PROXY="$build_HTTPS_PROXY" \
	NO_PROXY="$build_NO_PROXY" \
	ALL_PROXY="$build_ALL_PROXY" \
	http_proxy="$build_http_proxy" \
	https_proxy="$build_https_proxy" \
	no_proxy="$build_no_proxy" \
	all_proxy="$build_all_proxy" \
		docker build \
		--secret "id=system_ca,src=$CA_CERT_FILE" \
		--build-arg HTTP_PROXY \
		--build-arg HTTPS_PROXY \
		--build-arg NO_PROXY \
		--build-arg ALL_PROXY \
		--build-arg http_proxy \
		--build-arg https_proxy \
		--build-arg no_proxy \
		--build-arg all_proxy \
		-t "$image" .
)

if [ "$PUSH" = 1 ]; then
	docker push "$image"
fi

digest_reference=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image" | \
	awk -v prefix="$repository@sha256:" 'index($0, prefix) == 1 { print; exit }')
if [ -n "$digest_reference" ]; then
	printf '%s\n' "$digest_reference"
	exit 0
fi

image_id=$(docker image inspect --format '{{.Id}}' "$image")
case "$image_id" in
	sha256:*) ;;
	*) die 'docker returned an invalid image digest' ;;
esac
printf '%s@%s\n' "$repository" "$image_id"
