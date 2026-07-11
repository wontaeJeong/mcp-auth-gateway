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
}

validate_inputs

image=$REGISTRY/mcp-platform/mcp-auth-gateway:$IMAGE_TAG
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/mcp-auth-gateway-image-test.XXXXXX") || die 'could not create temporary directory'
container_id=

cleanup() {
	status=$?
	trap - 0 HUP INT TERM
	if [ -n "$container_id" ]; then
		docker rm -f "$container_id" >/dev/null 2>&1 || :
	fi
	rm -rf "$temporary_directory"
	exit "$status"
}

trap cleanup 0
trap 'exit 1' HUP INT TERM

container_id=$(docker create "$image")

environment_file=$temporary_directory/environment
labels_file=$temporary_directory/labels
user_file=$temporary_directory/user
history_file=$temporary_directory/history
export_file=$temporary_directory/container.tar
save_file=$temporary_directory/image.tar
retained_ca_file=$temporary_directory/ca-certificates.crt

docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$image" >"$environment_file"
if grep -Eiq '^(HTTP_PROXY|HTTPS_PROXY|NO_PROXY|ALL_PROXY)=' "$environment_file"; then
	die 'image contains proxy environment configuration'
fi

docker inspect --format '{{range $key, $value := .Config.Labels}}{{println $key "=" $value}}{{end}}' "$image" >"$labels_file"
if grep -Eiq 'proxy' "$labels_file"; then
	die 'image contains proxy label configuration'
fi

docker inspect --format '{{.Config.User}}' "$image" >"$user_file"
IFS= read -r image_user <"$user_file" || image_user=
case "$image_user" in
	''|root|root:*|0|0:*) die 'image must run as a non-root user' ;;
esac

docker cp "$container_id:/etc/ssl/certs/ca-certificates.crt" "$retained_ca_file"
if ! cmp -s "$CA_CERT_FILE" "$retained_ca_file"; then
	die 'image CA bundle does not match CA_CERT_FILE'
fi

docker history --no-trunc "$image" >"$history_file"
docker export --output "$export_file" "$container_id"
docker save --output "$save_file" "$image"

if [ -n "${PROXY_SCAN_VALUE:-}" ]; then
	for artifact in "$history_file" "$export_file" "$save_file"; do
		if grep -Fq -- "$PROXY_SCAN_VALUE" "$artifact"; then
			die 'image artifact contains the configured proxy scan value'
		fi
	done
fi

printf '%s\n' 'image checks passed'
