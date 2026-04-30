#!/bin/bash

# Setup script for DHCP networking with macvlan
# This allows the container to get its own IP from your router

echo "🔍 Detecting network configuration..."

# Get the default route interface
INTERFACE=$(route get default | grep interface | awk '{print $2}')
echo "   Network interface: $INTERFACE"

# Get current IP and gateway
CURRENT_IP=$(ifconfig $INTERFACE | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}')
GATEWAY=$(route get default | grep gateway | awk '{print $2}')
echo "   Current IP: $CURRENT_IP"
echo "   Gateway: $GATEWAY"

# Calculate network (assume /24)
NETWORK=$(echo $CURRENT_IP | cut -d. -f1-3).0/24
echo "   Network: $NETWORK"

echo ""
echo "🔧 Creating macvlan network..."

# Remove existing network if it exists
docker network rm loki-macvlan 2>/dev/null || true

# Create the macvlan network
docker network create -d macvlan \
  --subnet=$NETWORK \
  --gateway=$GATEWAY \
  -o parent=$INTERFACE \
  loki-macvlan

if [ $? -eq 0 ]; then
    echo "✅ Network 'loki-macvlan' created successfully!"
    echo ""
    echo "🚀 Now you can run:"
    echo "   docker compose -f docker-compose.dhcp.yml up --build"
    echo ""
    echo "📡 The container will get its own IP (like 10.0.0.X) from your router"
    echo "   and auto-detection will work perfectly!"
else
    echo "❌ Failed to create network. Check your permissions and network settings."
fi