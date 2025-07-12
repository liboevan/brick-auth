#!/bin/bash
set -e

# Brick Auth Comprehensive Test Script (English)
# Covers basic and advanced authentication API tests with detailed output

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Config
AUTH_URL="http://localhost:17001"
GATEWAY_URL="http://localhost:17000"

print_header() {
    echo -e "${BLUE}======================================"
    echo -e "Brick Auth Test Suite"
    echo -e "======================================${NC}"
}

print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_step() { echo -e "${BLUE}-- $1 --${NC}"; }

make_request() {
    local method="$1"
    local url="$2"
    local data="$3"
    local headers="$4"
    if [ -n "$data" ]; then
        if [ -n "$headers" ]; then
            curl -s -X "$method" "$url" -H "$headers" -d "$data"
        else
            curl -s -X "$method" "$url" -d "$data"
        fi
    else
        if [ -n "$headers" ]; then
            curl -s -X "$method" "$url" -H "$headers"
        else
            curl -s -X "$method" "$url"
        fi
    fi
}

check_service() {
    print_step "Service Health Check"
    print_info "Checking $1 at $2/health ..."
    local resp=$(make_request GET "$2/health")
    echo "$resp"
    if echo "$resp" | grep -q 'healthy'; then
        print_info "$1 is healthy."
    else
        print_error "$1 health check failed!"
        exit 1
    fi
}

test_version() {
    print_step "Version Endpoint"
    print_info "Requesting $AUTH_URL/version ..."
    local resp=$(make_request GET "$AUTH_URL/version")
    echo "$resp"
    if echo "$resp" | grep -q 'version'; then
        print_info "Version endpoint works."
    else
        print_error "Version endpoint failed!"
        exit 1
    fi
}

test_default_users() {
    print_step "Default User Existence"
    for user in "brick-super-admin" "brick-admin" "brick"; do
        print_info "Testing login for default user: $user ..."
        local resp=$(make_request POST "$AUTH_URL/login" "{\"username\":\"$user\",\"password\":\"brickpass\"}" "Content-Type: application/json")
        echo "$resp"
        if echo "$resp" | grep -q 'token'; then
            print_info "User $user exists and can login."
        else
            print_error "User $user login failed!"
            exit 1
        fi
    done
}

test_login_and_token_flow() {
    print_step "Login, Validate, Refresh, Me API"
    local username="$1"
    local password="$2"
    local expected_role="$3"
    print_info "Logging in as $username ..."
    local login_resp=$(make_request POST "$AUTH_URL/login" "{\"username\":\"$username\",\"password\":\"$password\"}" "Content-Type: application/json")
    echo "$login_resp"
    if ! echo "$login_resp" | grep -q 'token'; then
        print_error "Login failed for $username!"
        exit 1
    fi
    local token=$(echo "$login_resp" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    print_info "Token acquired: $token"

    print_info "Validating token ..."
    local val_resp=$(make_request POST "$AUTH_URL/validate" "" "Authorization: Bearer $token")
    echo "$val_resp"
    if echo "$val_resp" | grep -q 'valid.*true'; then
        print_info "Token is valid."
    else
        print_error "Token validation failed!"
        exit 1
    fi
    if [ -n "$expected_role" ] && ! echo "$val_resp" | grep -q "\"role\":\"$expected_role\""; then
        print_warn "Role mismatch: expected $expected_role"
    fi

    print_info "Refreshing token ..."
    local ref_resp=$(make_request POST "$AUTH_URL/refresh" "" "Authorization: Bearer $token")
    echo "$ref_resp"
    if echo "$ref_resp" | grep -q 'token'; then
        print_info "Token refresh succeeded."
    else
        print_error "Token refresh failed!"
        exit 1
    fi
    local new_token=$(echo "$ref_resp" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

    print_info "Getting user info ..."
    local me_resp=$(make_request GET "$AUTH_URL/me" "" "Authorization: Bearer $new_token")
    echo "$me_resp"
    if echo "$me_resp" | grep -q "$username"; then
        print_info "User info retrieved."
    else
        print_error "User info retrieval failed!"
        exit 1
    fi
}

test_invalid_login() {
    print_step "Invalid Login"
    print_info "Testing login with wrong credentials ..."
    local resp=$(make_request POST "$AUTH_URL/login" '{"username":"notexist","password":"wrong"}' "Content-Type: application/json")
    echo "$resp"
    if echo "$resp" | grep -q 'Invalid credentials'; then
        print_info "Invalid login correctly rejected."
    else
        print_error "Invalid login not rejected!"
        exit 1
    fi
}

test_invalid_token() {
    print_step "Invalid Token Validation"
    print_info "Testing /validate with invalid token ..."
    local resp=$(make_request POST "$AUTH_URL/validate" "" "Authorization: Bearer invalidtoken")
    echo "$resp"
    if echo "$resp" | grep -q 'Invalid token'; then
        print_info "Invalid token correctly rejected."
    else
        print_error "Invalid token not rejected!"
        exit 1
    fi
}

test_gateway_integration() {
    print_step "Gateway Integration (if available)"
    print_info "Testing /api/auth/health via gateway ..."
    local resp=$(make_request GET "$GATEWAY_URL/api/auth/health")
    echo "$resp"
    if echo "$resp" | grep -q 'healthy'; then
        print_info "Gateway health check passed."
    else
        print_warn "Gateway health check failed or not available."
    fi
}

test_super_admin_apis() {
    print_step "Super Admin APIs"
    print_info "Logging in as super-admin to test admin APIs ..."
    local login_resp=$(make_request POST "$AUTH_URL/login" '{"username":"brick-super-admin","password":"brickpass"}' "Content-Type: application/json")
    local token=$(echo "$login_resp" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    print_info "Super-admin token acquired"

    # Test user management
    print_info "Testing user list API ..."
    local users_resp=$(make_request GET "$AUTH_URL/admin/users" "" "Authorization: Bearer $token")
    echo "$users_resp"
    if echo "$users_resp" | grep -q 'users'; then
        print_info "User list API works."
    else
        print_error "User list API failed!"
        return 1
    fi

    # Test role management
    print_info "Testing role list API ..."
    local roles_resp=$(make_request GET "$AUTH_URL/admin/roles" "" "Authorization: Bearer $token")
    echo "$roles_resp"
    if echo "$roles_resp" | grep -q 'roles'; then
        print_info "Role list API works."
    else
        print_error "Role list API failed!"
        return 1
    fi

    # Test permission management
    print_info "Testing permission list API ..."
    local perms_resp=$(make_request GET "$AUTH_URL/admin/permissions" "" "Authorization: Bearer $token")
    echo "$perms_resp"
    if echo "$perms_resp" | grep -q 'permissions'; then
        print_info "Permission list API works."
    else
        print_error "Permission list API failed!"
        return 1
    fi

    # Test creating a new role
    print_info "Testing role creation API ..."
    local new_role_resp=$(make_request POST "$AUTH_URL/admin/roles" '{"name":"test-role","description":"Test role for API testing"}' "Authorization: Bearer $token" "Content-Type: application/json")
    echo "$new_role_resp"
    if echo "$new_role_resp" | grep -q 'Role created successfully'; then
        print_info "Role creation API works."
    else
        print_error "Role creation API failed!"
        return 1
    fi

    print_info "Super admin APIs test completed successfully."
}

test_admin_access_control() {
    print_step "Admin Access Control"
    print_info "Testing admin access with non-super-admin user ..."
    local login_resp=$(make_request POST "$AUTH_URL/login" '{"username":"brick-admin","password":"brickpass"}' "Content-Type: application/json")
    local token=$(echo "$login_resp" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    print_info "Admin token acquired"

    # Test that admin cannot access super-admin APIs
    print_info "Testing admin access to super-admin APIs (should fail) ..."
    local users_resp=$(make_request GET "$AUTH_URL/admin/users" "" "Authorization: Bearer $token")
    echo "$users_resp"
    if echo "$users_resp" | grep -q 'Super-admin access required'; then
        print_info "Access control working correctly - admin cannot access super-admin APIs."
    else
        print_error "Access control failed - admin should not be able to access super-admin APIs!"
        return 1
    fi

    print_info "Admin access control test completed successfully."
}

# Main test runner
run_tests() {
    print_header
    check_service "Brick Auth" "$AUTH_URL"
    test_version
    test_default_users
    test_login_and_token_flow "brick-super-admin" "brickpass" "super-admin"
    test_login_and_token_flow "brick-admin" "brickpass" "admin"
    test_login_and_token_flow "brick" "brickpass" "user"
    test_invalid_login
    test_invalid_token
    test_super_admin_apis
    test_admin_access_control
    test_gateway_integration
    print_header
    print_info "All tests completed. If no errors above, all tests passed!"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_tests
fi 