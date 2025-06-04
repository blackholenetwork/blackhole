# CI/CD Pipeline Configuration Template

## Pipeline Overview

**Pipeline Name:** [Project Name] CI/CD Pipeline  
**Repository:** [Git repository URL]  
**Branch Strategy:** GitFlow / GitHub Flow / Trunk-based  
**Deployment Targets:** Development → Staging → Production  

## Pipeline Architecture

```yaml
# Pipeline Flow Diagram
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Commit    │────▶│    Build    │────▶│    Test     │────▶│   Package   │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                                                                      │
                    ┌─────────────┐     ┌─────────────┐              ▼
                    │   Deploy    │◀────│   Publish   │     ┌─────────────┐
                    └─────────────┘     └─────────────┘     │   Security  │
                            │                                └─────────────┘
                            ▼
                    ┌─────────────┐
                    │   Monitor   │
                    └─────────────┘
```

## Environment Configuration

### Development Environment
```yaml
environment: development
url: https://dev.example.com
deployment:
  automatic: true
  branch: develop
  approval_required: false
variables:
  NODE_ENV: development
  API_URL: https://api-dev.example.com
  LOG_LEVEL: debug
```

### Staging Environment
```yaml
environment: staging
url: https://staging.example.com
deployment:
  automatic: true
  branch: main
  approval_required: false
variables:
  NODE_ENV: staging
  API_URL: https://api-staging.example.com
  LOG_LEVEL: info
```

### Production Environment
```yaml
environment: production
url: https://www.example.com
deployment:
  automatic: false
  branch: main
  approval_required: true
  approvers: ["tech-lead", "product-owner"]
variables:
  NODE_ENV: production
  API_URL: https://api.example.com
  LOG_LEVEL: error
```

## Pipeline Stages

### 1. Validation Stage
```yaml
validation:
  stage: validate
  timeout: 5 minutes
  parallel:
    - job: lint
      script:
        - npm run lint
        - npm run format:check
    - job: audit
      script:
        - npm audit --production
        - pip-audit check
    - job: secrets
      script:
        - trufflehog filesystem . --only-verified
        - git-secrets --scan
```

### 2. Build Stage
```yaml
build:
  stage: build
  timeout: 10 minutes
  cache:
    key: "$CI_COMMIT_REF_SLUG"
    paths:
      - node_modules/
      - .npm/
      - target/
  artifacts:
    paths:
      - dist/
      - build/
    expire_in: 1 week
  script:
    - echo "Building version $CI_COMMIT_SHA"
    - npm ci --cache .npm --prefer-offline
    - npm run build
    - echo "$CI_COMMIT_SHA" > dist/version.txt
```

### 3. Test Stage
```yaml
test:
  stage: test
  timeout: 15 minutes
  parallel:
    - job: unit-tests
      coverage: '/Coverage: \d+\.\d+%/'
      script:
        - npm run test:unit -- --coverage
        - npm run test:coverage-report
      artifacts:
        reports:
          coverage_report:
            coverage_format: cobertura
            path: coverage/cobertura-coverage.xml
    
    - job: integration-tests
      services:
        - postgres:14
        - redis:7
      script:
        - npm run test:integration
    
    - job: e2e-tests
      services:
        - name: selenium/standalone-chrome
      script:
        - npm run test:e2e
```

### 4. Security Scanning Stage
```yaml
security:
  stage: security
  timeout: 10 minutes
  parallel:
    - job: sast
      script:
        - semgrep --config=auto --json -o sast-report.json .
      artifacts:
        reports:
          sast: sast-report.json
    
    - job: dependency-check
      script:
        - npm audit --json > npm-audit.json
        - safety check --json > safety-report.json
        - snyk test --json > snyk-report.json
    
    - job: container-scan
      script:
        - trivy image --severity HIGH,CRITICAL $IMAGE_NAME
        - grype $IMAGE_NAME -o json > grype-report.json
```

### 5. Build Container Stage
```yaml
build-image:
  stage: package
  timeout: 10 minutes
  script:
    - echo "Building Docker image..."
    - docker build 
        --build-arg VERSION=$CI_COMMIT_SHA 
        --build-arg BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ") 
        -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA 
        -t $CI_REGISTRY_IMAGE:latest .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    - docker push $CI_REGISTRY_IMAGE:latest
```

### 6. Deploy Stage
```yaml
deploy-dev:
  stage: deploy
  environment: development
  script:
    - kubectl set image deployment/app app=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    - kubectl rollout status deployment/app
    - ./scripts/smoke-test.sh dev

deploy-staging:
  stage: deploy
  environment: staging
  when: manual
  script:
    - helm upgrade --install app ./helm 
        --set image.tag=$CI_COMMIT_SHA 
        --set environment=staging
    - ./scripts/smoke-test.sh staging

deploy-production:
  stage: deploy
  environment: production
  when: manual
  only:
    - tags
  script:
    - helm upgrade --install app ./helm 
        --set image.tag=$CI_COMMIT_TAG 
        --set environment=production
        --set replicas=3
    - ./scripts/smoke-test.sh production
    - ./scripts/notify-deployment.sh
```

## Quality Gates

### Code Quality Gates
```yaml
quality_gates:
  code_coverage:
    threshold: 80%
    fail_on_decrease: true
  
  code_smells:
    max_allowed: 10
    severity: major
  
  duplicated_lines:
    max_percentage: 5%
  
  cyclomatic_complexity:
    max_value: 10
```

### Performance Gates
```yaml
performance_gates:
  page_load_time:
    max_seconds: 2
    percentile: 95
  
  api_response_time:
    max_milliseconds: 200
    percentile: 99
  
  bundle_size:
    max_mb: 5
    fail_on_increase: 10%
```

## Rollback Strategy

### Automatic Rollback Triggers
```yaml
rollback_conditions:
  - error_rate > 5%
  - response_time_p99 > 1000ms
  - health_check_failures > 3
  - deployment_timeout > 10m
```

### Manual Rollback Procedure
```bash
#!/bin/bash
# Rollback to previous version
PREVIOUS_VERSION=$(kubectl rollout history deployment/app | tail -2 | head -1 | awk '{print $1}')
kubectl rollout undo deployment/app --to-revision=$PREVIOUS_VERSION
kubectl rollout status deployment/app

# Verify rollback
./scripts/health-check.sh
./scripts/smoke-test.sh
```

## Notifications and Monitoring

### Slack Notifications
```yaml
notifications:
  slack:
    channel: "#deployments"
    events:
      - pipeline_started
      - pipeline_failed
      - deployment_started
      - deployment_completed
      - rollback_triggered
```

### Monitoring Integration
```yaml
monitoring:
  datadog:
    api_key: $DATADOG_API_KEY
    tags:
      - "service:$CI_PROJECT_NAME"
      - "version:$CI_COMMIT_SHA"
      - "environment:$CI_ENVIRONMENT_NAME"
  
  prometheus:
    pushgateway: http://prometheus-pushgateway:9091
    job_name: "ci_pipeline"
```

## Pipeline Configuration Examples

### GitHub Actions Example
```yaml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: npm ci
      - run: npm run lint
      - run: npm run format:check

  test:
    needs: validate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: npm ci
      - run: npm test -- --coverage
      - uses: codecov/codecov-action@v3

  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: docker/setup-buildx-action@v2
      - uses: docker/login-action@v2
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v4
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}
```

### GitLab CI Example
```yaml
stages:
  - validate
  - build
  - test
  - security
  - package
  - deploy

variables:
  DOCKER_DRIVER: overlay2
  DOCKER_TLS_CERTDIR: ""

include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml

# Stage implementations...
```

## Maintenance and Optimization

### Pipeline Optimization Checklist
- [ ] Cache dependencies appropriately
- [ ] Parallelize independent jobs
- [ ] Use shallow clones for large repos
- [ ] Optimize Docker layer caching
- [ ] Remove unnecessary steps
- [ ] Use appropriate runner sizes

### Regular Maintenance Tasks
- [ ] Update base images monthly
- [ ] Review and update dependencies
- [ ] Clean up old artifacts
- [ ] Review pipeline metrics
- [ ] Update security scanning rules
- [ ] Test rollback procedures

## Troubleshooting Guide

### Common Issues and Solutions

#### Build Failures
```bash
# Clear cache
docker system prune -a
npm cache clean --force

# Rebuild with verbose logging
npm ci --verbose
docker build --no-cache --progress=plain .
```

#### Test Flakiness
```bash
# Retry flaky tests
npm test -- --retry=3

# Increase timeouts
TIMEOUT=30000 npm test
```

#### Deployment Issues
```bash
# Check deployment status
kubectl describe deployment app
kubectl logs -l app=myapp --tail=100

# Force new deployment
kubectl rollout restart deployment/app
```

## Security Best Practices

### Secrets Management
- Never commit secrets to repository
- Use CI/CD platform secret management
- Rotate secrets regularly
- Audit secret access

### Supply Chain Security
- Sign container images
- Generate SBOM for all releases
- Scan dependencies before deployment
- Verify artifact integrity

### Access Control
- Use least privilege principles
- Require approval for production
- Audit deployment permissions
- Use temporary credentials

---

## References
- [CI/CD Best Practices Guide]
- [Security Scanning Tools Documentation]
- [Deployment Strategy Patterns]
- [Pipeline Optimization Techniques]