#!/bin/bash
# Generate a new plugin from templates

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check arguments
if [ $# -lt 3 ]; then
    echo -e "${RED}Usage: $0 <type> <name> <description>${NC}"
    echo -e "  type: core, resource, data, service, economic"
    echo -e "  name: plugin name (e.g., storage)"
    echo -e "  description: brief description"
    echo ""
    echo -e "Example: $0 resource storage \"Distributed storage with erasure coding\""
    exit 1
fi

TYPE=$1
NAME=$2
DESCRIPTION=$3

# Convert name to package name (lowercase, replace - with _)
PACKAGE_NAME=$(echo "$NAME" | tr '[:upper:]' '[:lower:]' | sed 's/-/_/g')

# Set default values
VERSION="0.1.0"
AUTHOR="Blackhole Team"
LICENSE="MIT"

# Determine target directory based on type
case $TYPE in
    core)
        TARGET_DIR="pkg/core/$PACKAGE_NAME"
        ;;
    resource)
        TARGET_DIR="pkg/resources/$PACKAGE_NAME"
        ;;
    data)
        TARGET_DIR="pkg/data/$PACKAGE_NAME"
        ;;
    service)
        TARGET_DIR="pkg/service/$PACKAGE_NAME"
        ;;
    economic)
        TARGET_DIR="pkg/economic/$PACKAGE_NAME"
        ;;
    *)
        echo -e "${RED}Invalid type: $TYPE${NC}"
        exit 1
        ;;
esac

# Check if plugin already exists
if [ -d "$TARGET_DIR" ]; then
    echo -e "${RED}Plugin already exists: $TARGET_DIR${NC}"
    exit 1
fi

# Create plugin directory
echo -e "${GREEN}Creating plugin: $NAME${NC}"
echo -e "${GREEN}Type: $TYPE${NC}"
echo -e "${GREEN}Directory: $TARGET_DIR${NC}"

mkdir -p "$TARGET_DIR"

# Process templates
TEMPLATE_DIR="scripts/templates/plugin"

# Function to process template
process_template() {
    local template=$1
    local output=$2
    
    # Replace Go template syntax with actual values
    sed -e "s/{{\.PackageName}}/$PACKAGE_NAME/g" \
        -e "s/{{\.Name}}/$NAME/g" \
        -e "s/{{\.Type}}/$TYPE/g" \
        -e "s/{{\.Description}}/$DESCRIPTION/g" \
        -e "s/{{\.Version}}/$VERSION/g" \
        -e "s/{{\.Author}}/$AUTHOR/g" \
        -e "s/{{\.License}}/$LICENSE/g" \
        "$template" > "$output"
}

# Generate plugin.go
process_template "$TEMPLATE_DIR/base.go.tmpl" "$TARGET_DIR/plugin.go"
echo -e "${GREEN}✓ Created $TARGET_DIR/plugin.go${NC}"

# Generate plugin_test.go
process_template "$TEMPLATE_DIR/plugin_test.go.tmpl" "$TARGET_DIR/plugin_test.go"
echo -e "${GREEN}✓ Created $TARGET_DIR/plugin_test.go${NC}"

# Generate README.md
process_template "$TEMPLATE_DIR/README.md.tmpl" "$TARGET_DIR/README.md"
echo -e "${GREEN}✓ Created $TARGET_DIR/README.md${NC}"

# Format the generated code
echo -e "${YELLOW}Formatting code...${NC}"
go fmt "$TARGET_DIR/..."

echo -e "${GREEN}✅ Plugin created successfully!${NC}"
echo ""
echo -e "Next steps:"
echo -e "1. Implement your plugin logic in $TARGET_DIR/plugin.go"
echo -e "2. Add tests in $TARGET_DIR/plugin_test.go"
echo -e "3. Run tests: go test -v ./$TARGET_DIR/"
echo -e "4. Register plugin in the orchestrator"