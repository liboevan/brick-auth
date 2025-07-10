#!/bin/bash

# Debug info
which curl
curl --version
hostname
id
curl -v http://localhost:17001/version

# Source shared configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

print_header "API Testing"

API_BASE="${1:-localhost:$API_PORT}"
BASE_URL="http://$API_BASE"

print_info "Testing Brick Auth API at $BASE_URL"
echo "======================================"

# Wait for API to be ready
for i in {1..30}; do
    if curl -s "$BASE_URL/version" > /dev/null 2>&1; then
        print_info "API is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        print_error "API failed to start within 30 seconds"
        exit 1
    fi
    sleep 1
done

total_tests=0
passed_tests=0
failed_tests=0

run_test() {
    local desc="$1"
    local cmd="$2"
    total_tests=$((total_tests + 1))
    echo -e "\n--- Testing: $desc ---"
    eval "$cmd"
    local status=$?
    if [ $status -eq 0 ]; then
        passed_tests=$((passed_tests + 1))
    else
        failed_tests=$((failed_tests + 1))
    fi
}

# 0. Version endpoint
run_test "/version endpoint" '
resp=$(curl -s -w "\n%{http_code}" "$BASE_URL/version")
code=$(echo "$resp" | tail -n1)
echo "Status: $code"
echo "$resp" | head -n-1
if [ "$code" = "200" ]; then return 0; else return 1; fi
'

# 1. Login as brick-admin (should succeed)
run_test "/login with brick-admin:brickadminpass" '
resp=$(curl -s -w "\n%{http_code}" -X POST -H "Content-Type: application/json" -d "{\"username\":\"brick-admin\",\"password\":\"brickadminpass\"}" "$BASE_URL/login")
token=$(echo "$resp" | head -n1 | jq -r .token)
code=$(echo "$resp" | tail -n1)
echo "Status: $code"
echo "Token: $token"
if [ "$code" = "200" ] && [ "$token" != "null" ]; then return 0; else return 1; fi
'

# 2. Validate (should succeed)
run_test "/validate with valid token" '
resp=$(curl -s -w "\n%{http_code}" -X POST -H "Authorization: Bearer $token" "$BASE_URL/validate")
code=$(echo "$resp" | tail -n1)
echo "Status: $code"
echo "$resp" | head -n-1
if [ "$code" = "200" ]; then return 0; else return 1; fi
'

# 3. Me (should succeed)
run_test "/me with valid token" '
resp=$(curl -s -w "\n%{http_code}" -X GET -H "Authorization: Bearer $token" "$BASE_URL/me")
code=$(echo "$resp" | tail -n1)
echo "Status: $code"
echo "$resp" | head -n-1
if [ "$code" = "200" ]; then return 0; else return 1; fi
'

# 4. Refresh (should succeed)
run_test "/refresh with valid token" '
resp=$(curl -s -w "\n%{http_code}" -X POST -H "Authorization: Bearer $token" "$BASE_URL/refresh")
new_token=$(echo "$resp" | head -n1 | jq -r .token)
code=$(echo "$resp" | tail -n1)
echo "Status: $code"
echo "New Token: $new_token"
if [ "$code" = "200" ] && [ "$new_token" != "null" ]; then token=$new_token; return 0; else return 1; fi
'

# 5. Login as brick (should succeed)
run_test "/login with brick:brickpass" '
resp=$(curl -s -w "\n%{http_code}" -X POST -H "Content-Type: application/json" -d "{\"username\":\"brick\",\"password\":\"brickpass\"}" "$BASE_URL/login")
user_token=$(echo "$resp" | head -n1 | jq -r .token)
code=$(echo "$resp" | tail -n1)
echo "Status: $code"
echo "Token: $user_token"
if [ "$code" = "200" ] && [ "$user_token" != "null" ]; then return 0; else return 1; fi
'

# 6. Validate with refreshed token (should succeed)
run_test "/validate with refreshed token" '
resp=$(curl -s -w "\n%{http_code}" -X POST -H "Authorization: Bearer $token" "$BASE_URL/validate")
code=$(echo "$resp" | tail -n1)
echo "Status: $code"
echo "$resp" | head -n-1
if [ "$code" = "200" ]; then return 0; else return 1; fi
'

# 7. Validate with invalid token (should fail)
run_test "/validate with invalid token" '
resp=$(curl -s -w "\n%{http_code}" -X POST -H "Authorization: Bearer invalidtoken" "$BASE_URL/validate")
code=$(echo "$resp" | tail -n1)
echo "Status: $code"
echo "$resp" | head -n-1
if [ "$code" = "401" ]; then return 0; else return 1; fi
'

# 8. Me with invalid token (should fail)
run_test "/me with invalid token" '
resp=$(curl -s -w "\n%{http_code}" -X GET -H "Authorization: Bearer invalidtoken" "$BASE_URL/me")
code=$(echo "$resp" | tail -n1)
echo "Status: $code"
echo "$resp" | head -n-1
if [ "$code" = "401" ]; then return 0; else return 1; fi
'

# 9. Refresh with invalid token (should fail)
run_test "/refresh with invalid token" '
resp=$(curl -s -w "\n%{http_code}" -X POST -H "Authorization: Bearer invalidtoken" "$BASE_URL/refresh")
code=$(echo "$resp" | tail -n1)
echo "Status: $code"
echo "$resp" | head -n-1
if [ "$code" = "401" ]; then return 0; else return 1; fi
'

echo -e "\n======================================"
echo -e "${BLUE}Test Summary:${NC}"
echo -e "Total Tests: $total_tests"
echo -e "Passed: ${GREEN}$passed_tests${NC}"
echo -e "Failed: ${RED}$failed_tests${NC}"

if [ $failed_tests -eq 0 ]; then
    print_info "All tests passed! 🎉"
    exit 0
else
    print_error "Some tests failed. Please check the responses above."
    exit 1
fi 