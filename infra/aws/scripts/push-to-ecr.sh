#!/bin/bash
# ===========================================
# PadmaVue.ai - Push Docker Images to ECR
# ===========================================

set -e

# Configuration
AWS_REGION=${AWS_REGION:-"us-east-1"}
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
APP_NAME="padmavue"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}PadmaVue.ai - ECR Push Script${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo "AWS Region: ${AWS_REGION}"
echo "AWS Account ID: ${AWS_ACCOUNT_ID}"
echo "ECR Registry: ${ECR_REGISTRY}"
echo ""

# Authenticate with ECR
echo -e "${YELLOW}Authenticating with ECR...${NC}"
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ECR_REGISTRY}

# Build and push backend
echo -e "${YELLOW}Building backend image...${NC}"
cd ../../../backend
docker build -t ${APP_NAME}-backend:latest .
docker tag ${APP_NAME}-backend:latest ${ECR_REGISTRY}/${APP_NAME}-backend:latest
docker tag ${APP_NAME}-backend:latest ${ECR_REGISTRY}/${APP_NAME}-backend:$(git rev-parse --short HEAD)

echo -e "${YELLOW}Pushing backend image...${NC}"
docker push ${ECR_REGISTRY}/${APP_NAME}-backend:latest
docker push ${ECR_REGISTRY}/${APP_NAME}-backend:$(git rev-parse --short HEAD)
echo -e "${GREEN}Backend image pushed successfully!${NC}"

# Build and push frontend
echo -e "${YELLOW}Building frontend image...${NC}"
cd ../frontend
docker build -t ${APP_NAME}-frontend:latest .
docker tag ${APP_NAME}-frontend:latest ${ECR_REGISTRY}/${APP_NAME}-frontend:latest
docker tag ${APP_NAME}-frontend:latest ${ECR_REGISTRY}/${APP_NAME}-frontend:$(git rev-parse --short HEAD)

echo -e "${YELLOW}Pushing frontend image...${NC}"
docker push ${ECR_REGISTRY}/${APP_NAME}-frontend:latest
docker push ${ECR_REGISTRY}/${APP_NAME}-frontend:$(git rev-parse --short HEAD)
echo -e "${GREEN}Frontend image pushed successfully!${NC}"

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}All images pushed successfully!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo "Backend: ${ECR_REGISTRY}/${APP_NAME}-backend:latest"
echo "Frontend: ${ECR_REGISTRY}/${APP_NAME}-frontend:latest"


