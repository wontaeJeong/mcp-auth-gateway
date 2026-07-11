#!/bin/sh
set -u

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/mcp-auth-gateway-container-test.XXXXXX") || exit 1
trap 'rm -rf "$test_tmp"' 0
trap 'exit 1' HUP INT TERM

failures=0
tests=0

pass() {
	tests=$((tests + 1))
	printf 'ok %d - %s\n' "$tests" "$1"
}

fail() {
	tests=$((tests + 1))
	failures=$((failures + 1))
	printf 'not ok %d - %s\n' "$tests" "$1"
}

assert_success() {
	description=$1
	shift
	if "$@" >"$test_tmp/output" 2>&1; then
		pass "$description"
	else
		fail "$description"
	fi
}

assert_failure() {
	description=$1
	shift
	if "$@" >"$test_tmp/output" 2>&1; then
		fail "$description"
	else
		pass "$description"
	fi
}

assert_file_contains() {
	description=$1
	file=$2
	text=$3
	if grep -Fq -- "$text" "$file"; then
		pass "$description"
	else
		fail "$description"
	fi
}

assert_file_excludes() {
	description=$1
	file=$2
	text=$3
	if grep -Fq -- "$text" "$file"; then
		fail "$description"
	else
		pass "$description"
	fi
}

mkdir "$test_tmp/bin"
cp "$script_dir/fake-docker" "$test_tmp/bin/docker"
chmod +x "$test_tmp/bin/docker"
fake_path=$test_tmp/bin:/usr/bin:/bin
docker_log=$test_tmp/docker.log
ca_file=$test_tmp/system-ca.pem
cat >"$ca_file" <<'EOF'
-----BEGIN CERTIFICATE-----
ZHVtbXktY2VydGlmaWNhdGU=
-----END CERTIFICATE-----
EOF

run_build() {
	env -i \
		PATH="$fake_path" HOME="$test_tmp" TMPDIR="$test_tmp" \
		REGISTRY=registry.example.com IMAGE_TAG=0123456789abcdef \
		CA_CERT_FILE="$ca_file" FAKE_DOCKER_LOG="$docker_log" \
		FAKE_DOCKER_CA_SOURCE="$ca_file" "$@" \
		sh "$repo_root/scripts/build-and-push.sh"
}

run_image_test() {
	env -i \
		PATH="$fake_path" HOME="$test_tmp" TMPDIR="$test_tmp" \
		REGISTRY=registry.example.com IMAGE_TAG=0123456789abcdef \
		CA_CERT_FILE="$ca_file" FAKE_DOCKER_LOG="$docker_log" \
		FAKE_DOCKER_CA_SOURCE="$ca_file" "$@" \
		sh "$repo_root/scripts/test-image.sh"
}

run_build_with_relative_ca() {
	(
		cd "$test_tmp" || exit 1
		env -i \
			PATH="$fake_path" HOME="$test_tmp" TMPDIR="$test_tmp" \
			REGISTRY=registry.example.com IMAGE_TAG=0123456789abcdef \
			CA_CERT_FILE=system-ca.pem FAKE_DOCKER_LOG="$docker_log" \
			FAKE_DOCKER_CA_SOURCE="$ca_file" \
			sh "$repo_root/scripts/build-and-push.sh"
	)
}

: >"$docker_log"
assert_failure 'build rejects a missing registry' env -i \
	PATH="$fake_path" HOME="$test_tmp" TMPDIR="$test_tmp" IMAGE_TAG=0123456789abcdef \
	CA_CERT_FILE="$ca_file" FAKE_DOCKER_LOG="$docker_log" \
	sh "$repo_root/scripts/build-and-push.sh"
assert_failure 'build rejects a missing image tag' env -i \
	PATH="$fake_path" HOME="$test_tmp" TMPDIR="$test_tmp" REGISTRY=registry.example.com \
	CA_CERT_FILE="$ca_file" FAKE_DOCKER_LOG="$docker_log" \
	sh "$repo_root/scripts/build-and-push.sh"
assert_failure 'build rejects a missing CA file' env -i \
	PATH="$fake_path" HOME="$test_tmp" TMPDIR="$test_tmp" REGISTRY=registry.example.com \
	IMAGE_TAG=0123456789abcdef FAKE_DOCKER_LOG="$docker_log" \
	sh "$repo_root/scripts/build-and-push.sh"

for tag in latest dev development local test changeme placeholder IMAGE_TAG; do
	assert_failure "build rejects mutable or placeholder tag: $tag" run_build IMAGE_TAG="$tag"
done

empty_ca=$test_tmp/empty.pem
: >"$empty_ca"
assert_failure 'build rejects an empty CA file' run_build CA_CERT_FILE="$empty_ca"
invalid_ca=$test_tmp/invalid.pem
printf '%s\n' 'not a PEM certificate bundle' >"$invalid_ca"
assert_failure 'build rejects a non-PEM CA file' run_build CA_CERT_FILE="$invalid_ca"
assert_failure 'image test rejects a non-PEM CA file' run_image_test \
	CA_CERT_FILE="$invalid_ca" FAKE_DOCKER_CA_SOURCE="$invalid_ca"
assert_failure 'build rejects invalid PUSH values' run_build PUSH=2

: >"$docker_log"
assert_failure 'build fails closed when docker build has no secret support' run_build FAKE_DOCKER_SECRET_SUPPORT=0
assert_file_excludes 'unsupported builder is not used for a build' "$docker_log" 'ARG=--secret'

: >"$docker_log"
assert_success 'capability probe uses BuildKit help when legacy help lacks secrets' run_build \
	FAKE_DOCKER_SECRET_REQUIRES_BUILDKIT=1
assert_file_contains 'capability probe enables BuildKit in command scope' "$docker_log" \
	'HELP_ENV_DOCKER_BUILDKIT=1'

: >"$docker_log"
proxy_scan_value='proxy-contract-value.invalid:8443'
assert_success 'build accepts a git SHA and BuildKit secret support' run_build \
	PROXY="$proxy_scan_value" NO_PROXY=localhost no_proxy=127.0.0.1
assert_file_contains 'build uses the exact immutable image name' "$docker_log" \
	'ARG=registry.example.com/mcp-platform/mcp-auth-gateway:0123456789abcdef'
assert_file_contains 'build enables BuildKit in command scope' "$docker_log" 'BUILD_ENV_DOCKER_BUILDKIT=1'
assert_file_contains 'build passes the CA as a BuildKit secret' "$docker_log" 'ARG=id=system_ca,src='
for name in HTTP_PROXY HTTPS_PROXY NO_PROXY ALL_PROXY http_proxy https_proxy no_proxy all_proxy; do
	assert_file_contains "build passes predefined proxy argument $name by name" "$docker_log" "ARG=$name"
	assert_file_excludes "build does not put the $name value in an argument" "$docker_log" "ARG=$name="
done
assert_file_contains 'PROXY falls back to upper-case HTTP proxy' "$docker_log" \
	"BUILD_ENV_HTTP_PROXY=$proxy_scan_value"
assert_file_contains 'PROXY falls back to lower-case HTTPS proxy' "$docker_log" \
	"BUILD_ENV_https_proxy=$proxy_scan_value"
assert_file_contains 'explicit NO_PROXY is preserved' "$docker_log" 'BUILD_ENV_NO_PROXY=localhost'
assert_file_excludes 'build output does not disclose proxy values' "$test_tmp/output" "$proxy_scan_value"
assert_file_contains 'build prints a digest reference' "$test_tmp/output" \
	'registry.example.com/mcp-platform/mcp-auth-gateway@sha256:0123456789abcdef'
assert_file_excludes 'PUSH defaults to disabled' "$docker_log" 'ARG=push'

: >"$docker_log"
assert_success 'build resolves a relative CA path before changing context' run_build_with_relative_ca
assert_file_contains 'build passes an absolute CA secret path' "$docker_log" \
	'ARG=id=system_ca,src=/'

: >"$docker_log"
assert_success 'PUSH=1 pushes the built image' run_build PUSH=1
assert_file_contains 'push uses plain docker push' "$docker_log" 'ARG=push'
assert_file_excludes 'pipeline does not use buildx' "$docker_log" 'ARG=buildx'

: >"$docker_log"
assert_success 'image test verifies a clean image and retained CA' run_image_test \
	PROXY_SCAN_VALUE="$proxy_scan_value"
assert_file_contains 'image test inspects image environment' "$docker_log" 'Config.Env'
assert_file_contains 'image test inspects image labels' "$docker_log" 'Config.Labels'
assert_file_contains 'image test checks the runtime user' "$docker_log" 'Config.User'
assert_file_contains 'image test scans image history' "$docker_log" 'ARG=history'
assert_file_contains 'image test scans a container export' "$docker_log" 'ARG=export'
assert_file_contains 'image test scans an image save' "$docker_log" 'ARG=save'
assert_file_contains 'image test removes its temporary container' "$docker_log" 'ARG=rm'
assert_file_excludes 'image test output does not disclose scan values' "$test_tmp/output" "$proxy_scan_value"

: >"$docker_log"
assert_failure 'image test rejects proxy environment metadata' run_image_test \
	FAKE_DOCKER_IMAGE_ENV="HTTPS_PROXY=$proxy_scan_value" PROXY_SCAN_VALUE="$proxy_scan_value"
assert_file_excludes 'proxy metadata failure does not disclose values' "$test_tmp/output" "$proxy_scan_value"
assert_file_contains 'proxy metadata failure still removes its container' "$docker_log" 'ARG=rm'

: >"$docker_log"
assert_failure 'image test rejects lowercase proxy environment metadata' run_image_test \
	FAKE_DOCKER_IMAGE_ENV="http_proxy=$proxy_scan_value" PROXY_SCAN_VALUE="$proxy_scan_value"
assert_file_excludes 'lowercase proxy metadata failure does not disclose values' "$test_tmp/output" "$proxy_scan_value"
assert_file_contains 'lowercase proxy metadata failure still removes its container' "$docker_log" 'ARG=rm'

: >"$docker_log"
assert_failure 'image test detects a proxy value in saved image data' run_image_test \
	FAKE_DOCKER_SAVE="$proxy_scan_value" PROXY_SCAN_VALUE="$proxy_scan_value"
assert_file_excludes 'saved-data failure does not disclose values' "$test_tmp/output" "$proxy_scan_value"
assert_file_contains 'saved-data failure still removes its container' "$docker_log" 'ARG=rm'

assert_file_contains 'Dockerfile mounts system CA for module download' "$repo_root/Dockerfile" \
	'RUN --mount=type=secret,id=system_ca'
if [ "$(grep -c -- 'RUN --mount=type=secret,id=system_ca' "$repo_root/Dockerfile")" -ge 2 ]; then
	pass 'Dockerfile mounts system CA for both dependency and build steps'
else
	fail 'Dockerfile mounts system CA for both dependency and build steps'
fi
assert_file_contains 'Dockerfile copies the exact supplied CA into the final image' "$repo_root/Dockerfile" \
	'/etc/ssl/certs/ca-certificates.crt'
if grep -Eiq '^[[:space:]]*(ARG|ENV)[[:space:]]+([A-Za-z_]*proxy)' "$repo_root/Dockerfile"; then
	fail 'Dockerfile has no proxy ARG or ENV declarations'
else
	pass 'Dockerfile has no proxy ARG or ENV declarations'
fi
assert_file_contains 'Dockerfile keeps the non-root runtime user' "$repo_root/Dockerfile" 'USER nonroot:nonroot'
assert_file_contains 'Dockerfile preserves the gateway entrypoint' "$repo_root/Dockerfile" 'ENTRYPOINT ["/gateway"]'
assert_file_contains 'Docker context excludes VCS data' "$repo_root/.dockerignore" '.git'
assert_file_contains 'Docker context excludes environment files' "$repo_root/.dockerignore" '.env'
assert_file_contains 'Docker context excludes private keys' "$repo_root/.dockerignore" '*.key'
assert_file_contains 'Docker context excludes certificate files' "$repo_root/.dockerignore" '*.pem'
assert_file_contains 'Docker context excludes build output' "$repo_root/.dockerignore" 'dist/'
assert_file_contains 'Docker context excludes pipeline scripts' "$repo_root/.dockerignore" 'scripts/'
assert_file_contains 'Docker context excludes repository tests' "$repo_root/.dockerignore" 'tests/'

if [ "$failures" -ne 0 ]; then
	printf '1..%d\n' "$tests"
	printf '%d test(s) failed\n' "$failures" >&2
	exit 1
fi

printf '1..%d\n' "$tests"
