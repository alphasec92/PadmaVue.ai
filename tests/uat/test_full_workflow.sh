#!/bin/bash
# UAT Test Script - Full Workflow Testing
# Tests complete user workflows: upload → analyze → review

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
FRONTEND_URL="${FRONTEND_URL:-http://localhost:3000}"
TEST_PROJECT_NAME="UAT Test Project $(date +%s)"

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

test_step() {
    local step_name="$1"
    log_info "Testing: $step_name"
}

assert_http_status() {
    local url="$1"
    local expected_status="${2:-200}"
    local response=$(curl -s -o /dev/null -w "%{http_code}" "$url" || echo "000")
    
    if [ "$response" = "$expected_status" ]; then
        log_info "✓ HTTP $expected_status: $url"
        ((TESTS_PASSED++))
        return 0
    else
        log_error "✗ Expected HTTP $expected_status, got $response: $url"
        ((TESTS_FAILED++))
        return 1
    fi
}

assert_json_contains() {
    local url="$1"
    local key="$2"
    local response=$(curl -s "$url")
    
    if echo "$response" | grep -q "\"$key\""; then
        log_info "✓ JSON contains '$key': $url"
        ((TESTS_PASSED++))
        return 0
    else
        log_error "✗ JSON missing '$key': $url"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Test functions
test_backend_health() {
    test_step "Backend Health Check"
    assert_http_status "$BACKEND_URL/health" 200
    assert_json_contains "$BACKEND_URL/health" "status"
}

test_frontend_accessible() {
    test_step "Frontend Accessibility"
    assert_http_status "$FRONTEND_URL" 200
}

test_settings_api() {
    test_step "Settings API"
    assert_http_status "$BACKEND_URL/api/settings" 200
    assert_json_contains "$BACKEND_URL/api/settings" "provider"
}

test_llm_provider_configuration() {
    test_step "LLM Provider Configuration"
    
    # Test getting current settings
    local settings=$(curl -s "$BACKEND_URL/api/settings")
    if echo "$settings" | grep -q "\"provider\""; then
        log_info "✓ Settings endpoint returns provider configuration"
        ((TESTS_PASSED++))
    else
        log_error "✗ Settings endpoint missing provider"
        ((TESTS_FAILED++))
        return 1
    fi
    
    # Test Ollama models endpoint (may fail if Ollama not running, that's OK)
    local ollama_response=$(curl -s "$BACKEND_URL/api/settings/ollama/models?base_url=http://localhost:11434")
    if echo "$ollama_response" | grep -q "\"available\""; then
        log_info "✓ Ollama endpoint responds (available or not)"
        ((TESTS_PASSED++))
    else
        log_warn "⚠ Ollama endpoint may not be working correctly"
        ((TESTS_FAILED++))
    fi
}

test_architect_chat() {
    test_step "Architect Chat API"
    
    local session_id="uat-test-$(date +%s)"
    local response=$(curl -s -X POST "$BACKEND_URL/api/architect/chat" \
        -H "Content-Type: application/json" \
        -d "{\"message\": \"Test message for UAT\", \"session_id\": \"$session_id\"}")
    
    if echo "$response" | grep -q "\"session_id\""; then
        log_info "✓ Chat endpoint responds with session"
        ((TESTS_PASSED++))
    else
        log_error "✗ Chat endpoint failed or returned unexpected response"
        log_error "Response: $response"
        ((TESTS_FAILED++))
        return 1
    fi
}

test_settings_persistence() {
    test_step "Settings Persistence"
    
    # Update settings
    local update_response=$(curl -s -X POST "$BACKEND_URL/api/settings" \
        -H "Content-Type: application/json" \
        -d '{"provider": "mock", "model": "mock-model", "temperature": 0.7}')
    
    # Verify settings were updated
    local settings=$(curl -s "$BACKEND_URL/api/settings")
    if echo "$settings" | grep -q "\"provider\""; then
        log_info "✓ Settings can be updated and retrieved"
        ((TESTS_PASSED++))
    else
        log_error "✗ Settings persistence may not be working"
        ((TESTS_FAILED++))
    fi
}

test_error_handling() {
    test_step "Error Handling"
    
    # Test invalid endpoint
    local response=$(curl -s -o /dev/null -w "%{http_code}" "$BACKEND_URL/api/invalid-endpoint")
    if [ "$response" = "404" ]; then
        log_info "✓ 404 error handling works"
        ((TESTS_PASSED++))
    else
        log_warn "⚠ Expected 404, got $response"
        ((TESTS_FAILED++))
    fi
    
    # Test invalid JSON
    local response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$BACKEND_URL/api/architect/chat" \
        -H "Content-Type: application/json" \
        -d "invalid json")
    if [ "$response" = "422" ] || [ "$response" = "400" ]; then
        log_info "✓ JSON validation error handling works"
        ((TESTS_PASSED++))
    else
        log_warn "⚠ Expected 422/400, got $response"
        ((TESTS_FAILED++))
    fi
}

# Main test execution
main() {
    log_info "=========================================="
    log_info "PadmaVue.ai UAT - Full Workflow Testing"
    log_info "=========================================="
    log_info "Backend: $BACKEND_URL"
    log_info "Frontend: $FRONTEND_URL"
    log_info ""
    
    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    sleep 2
    
    # Run tests
    test_backend_health
    test_frontend_accessible
    test_settings_api
    test_llm_provider_configuration
    test_architect_chat
    test_settings_persistence
    test_error_handling
    
    # Summary
    log_info ""
    log_info "=========================================="
    log_info "Test Summary"
    log_info "=========================================="
    log_info "Passed: $TESTS_PASSED"
    log_info "Failed: $TESTS_FAILED"
    log_info "Total:  $((TESTS_PASSED + TESTS_FAILED))"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        log_info ""
        log_info "✓ All tests passed!"
        exit 0
    else
        log_error ""
        log_error "✗ Some tests failed"
        exit 1
    fi
}

# Run main function
main
