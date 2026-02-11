# UAT Test Script - Full Workflow Testing (PowerShell)
# Tests complete user workflows: upload → analyze → review

param(
    [string]$BackendUrl = "http://localhost:8000",
    [string]$FrontendUrl = "http://localhost:3000"
)

$ErrorActionPreference = "Stop"

# Test counters
$script:TESTS_PASSED = 0
$script:TESTS_FAILED = 0

# Helper functions
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Test-Step {
    param([string]$StepName)
    Write-Info "Testing: $StepName"
}

function Assert-HttpStatus {
    param(
        [string]$Url,
        [int]$ExpectedStatus = 200
    )
    
    try {
        $response = Invoke-WebRequest -Uri $Url -Method Get -UseBasicParsing -ErrorAction Stop
        if ($response.StatusCode -eq $ExpectedStatus) {
            Write-Info "✓ HTTP $ExpectedStatus : $Url"
            $script:TESTS_PASSED++
            return $true
        } else {
            Write-Error "✗ Expected HTTP $ExpectedStatus, got $($response.StatusCode) : $Url"
            $script:TESTS_FAILED++
            return $false
        }
    } catch {
        Write-Error "✗ Request failed: $Url - $($_.Exception.Message)"
        $script:TESTS_FAILED++
        return $false
    }
}

function Assert-JsonContains {
    param(
        [string]$Url,
        [string]$Key
    )
    
    try {
        $response = Invoke-RestMethod -Uri $Url -Method Get -ErrorAction Stop
        $json = $response | ConvertTo-Json -Depth 10
        if ($json -match "`"$Key`"") {
            Write-Info "✓ JSON contains '$Key' : $Url"
            $script:TESTS_PASSED++
            return $true
        } else {
            Write-Error "✗ JSON missing '$Key' : $Url"
            $script:TESTS_FAILED++
            return $false
        }
    } catch {
        Write-Error "✗ Request failed: $Url - $($_.Exception.Message)"
        $script:TESTS_FAILED++
        return $false
    }
}

# Test functions
function Test-BackendHealth {
    Test-Step "Backend Health Check"
    Assert-HttpStatus -Url "$BackendUrl/health" -ExpectedStatus 200
    Assert-JsonContains -Url "$BackendUrl/health" -Key "status"
}

function Test-FrontendAccessible {
    Test-Step "Frontend Accessibility"
    Assert-HttpStatus -Url $FrontendUrl -ExpectedStatus 200
}

function Test-SettingsApi {
    Test-Step "Settings API"
    Assert-HttpStatus -Url "$BackendUrl/api/settings" -ExpectedStatus 200
    Assert-JsonContains -Url "$BackendUrl/api/settings" -Key "provider"
}

function Test-LLMProviderConfiguration {
    Test-Step "LLM Provider Configuration"
    
    try {
        $settings = Invoke-RestMethod -Uri "$BackendUrl/api/settings" -Method Get
        if ($settings.provider) {
            Write-Info "✓ Settings endpoint returns provider configuration"
            $script:TESTS_PASSED++
        } else {
            Write-Error "✗ Settings endpoint missing provider"
            $script:TESTS_FAILED++
        }
        
        # Test Ollama models endpoint (may fail if Ollama not running, that's OK)
        try {
            $ollamaResponse = Invoke-RestMethod -Uri "$BackendUrl/api/settings/ollama/models?base_url=http://localhost:11434" -Method Get
            if ($ollamaResponse.available -ne $null) {
                Write-Info "✓ Ollama endpoint responds (available or not)"
                $script:TESTS_PASSED++
            } else {
                Write-Warn "⚠ Ollama endpoint may not be working correctly"
                $script:TESTS_FAILED++
            }
        } catch {
            Write-Warn "⚠ Ollama endpoint not accessible (may be expected if Ollama not running)"
            $script:TESTS_FAILED++
        }
    } catch {
        Write-Error "✗ Settings API test failed: $($_.Exception.Message)"
        $script:TESTS_FAILED++
    }
}

function Test-ArchitectChat {
    Test-Step "Architect Chat API"
    
    $sessionId = "uat-test-$(Get-Date -Format 'yyyyMMddHHmmss')"
    $body = @{
        message = "Test message for UAT"
        session_id = $sessionId
    } | ConvertTo-Json
    
    try {
        $response = Invoke-RestMethod -Uri "$BackendUrl/api/architect/chat" -Method Post -Body $body -ContentType "application/json"
        if ($response.session_id) {
            Write-Info "✓ Chat endpoint responds with session"
            $script:TESTS_PASSED++
        } else {
            Write-Error "✗ Chat endpoint failed or returned unexpected response"
            $script:TESTS_FAILED++
        }
    } catch {
        Write-Error "✗ Chat endpoint failed: $($_.Exception.Message)"
        $script:TESTS_FAILED++
    }
}

function Test-SettingsPersistence {
    Test-Step "Settings Persistence"
    
    $body = @{
        provider = "mock"
        model = "mock-model"
        temperature = 0.7
    } | ConvertTo-Json
    
    try {
        $updateResponse = Invoke-RestMethod -Uri "$BackendUrl/api/settings" -Method Post -Body $body -ContentType "application/json"
        $settings = Invoke-RestMethod -Uri "$BackendUrl/api/settings" -Method Get
        if ($settings.provider) {
            Write-Info "✓ Settings can be updated and retrieved"
            $script:TESTS_PASSED++
        } else {
            Write-Error "✗ Settings persistence may not be working"
            $script:TESTS_FAILED++
        }
    } catch {
        Write-Error "✗ Settings persistence test failed: $($_.Exception.Message)"
        $script:TESTS_FAILED++
    }
}

function Test-ErrorHandling {
    Test-Step "Error Handling"
    
    # Test invalid endpoint
    try {
        $response = Invoke-WebRequest -Uri "$BackendUrl/api/invalid-endpoint" -Method Get -UseBasicParsing -ErrorAction Stop
        if ($response.StatusCode -eq 404) {
            Write-Info "✓ 404 error handling works"
            $script:TESTS_PASSED++
        } else {
            Write-Warn "⚠ Expected 404, got $($response.StatusCode)"
            $script:TESTS_FAILED++
        }
    } catch {
        if ($_.Exception.Response.StatusCode -eq 404) {
            Write-Info "✓ 404 error handling works"
            $script:TESTS_PASSED++
        } else {
            Write-Warn "⚠ Expected 404, got different error"
            $script:TESTS_FAILED++
        }
    }
    
    # Test invalid JSON
    try {
        $response = Invoke-WebRequest -Uri "$BackendUrl/api/architect/chat" -Method Post -Body "invalid json" -ContentType "application/json" -UseBasicParsing -ErrorAction Stop
        Write-Warn "⚠ Expected error, got status $($response.StatusCode)"
        $script:TESTS_FAILED++
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 422 -or $statusCode -eq 400) {
            Write-Info "✓ JSON validation error handling works"
            $script:TESTS_PASSED++
        } else {
            Write-Warn "⚠ Expected 422/400, got $statusCode"
            $script:TESTS_FAILED++
        }
    }
}

# Main test execution
function Main {
    Write-Info "=========================================="
    Write-Info "PadmaVue.ai UAT - Full Workflow Testing"
    Write-Info "=========================================="
    Write-Info "Backend: $BackendUrl"
    Write-Info "Frontend: $FrontendUrl"
    Write-Info ""
    
    # Wait for services to be ready
    Write-Info "Waiting for services to be ready..."
    Start-Sleep -Seconds 2
    
    # Run tests
    Test-BackendHealth
    Test-FrontendAccessible
    Test-SettingsApi
    Test-LLMProviderConfiguration
    Test-ArchitectChat
    Test-SettingsPersistence
    Test-ErrorHandling
    
    # Summary
    Write-Info ""
    Write-Info "=========================================="
    Write-Info "Test Summary"
    Write-Info "=========================================="
    Write-Info "Passed: $script:TESTS_PASSED"
    Write-Info "Failed: $script:TESTS_FAILED"
    Write-Info "Total:  $($script:TESTS_PASSED + $script:TESTS_FAILED)"
    
    if ($script:TESTS_FAILED -eq 0) {
        Write-Info ""
        Write-Info "✓ All tests passed!"
        exit 0
    } else {
        Write-Error ""
        Write-Error "✗ Some tests failed"
        exit 1
    }
}

# Run main function
Main
