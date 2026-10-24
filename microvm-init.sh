#!/usr/bin/env bash
# microvm-init.sh — Initialize an OS project from starter kit templates
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATES_DIR="$SCRIPT_DIR/starter-kit"

usage() {
    echo "Usage: microvm-init.sh <project-name> [--rust]"
    echo ""
    echo "Create a new OS project from microvm starter kit templates."
    echo ""
    echo "Options:"
    echo "  --rust    Use the Rust kernel template (default: C)"
    echo ""
    echo "Examples:"
    echo "  microvm-init.sh my-os          # C kernel"
    echo "  microvm-init.sh my-os --rust   # Rust kernel"
    exit 1
}

[[ $# -lt 1 ]] && usage

PROJECT_NAME="$1"
TEMPLATE="minimal-kernel"
[[ "${2:-}" == "--rust" ]] && TEMPLATE="rust-kernel"

if [[ -e "$PROJECT_NAME" ]]; then
    echo "Error: '$PROJECT_NAME' already exists."
    exit 1
fi

echo "🚀 Creating OS project '$PROJECT_NAME' from template '$TEMPLATE'..."
cp -r "$TEMPLATES_DIR/$TEMPLATE" "$PROJECT_NAME"

echo "✅ Done! Next steps:"
echo ""
echo "  cd $PROJECT_NAME"
echo "  make"
echo "  microvm run --kernel kernel.bin --load-addr 0x80000000"
echo ""
echo "📖 Tutorials: https://github.com/quantumnic/microvm/tree/main/docs/tutorials"
