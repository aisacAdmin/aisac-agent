#!/bin/bash
# Generate development certificates for AISAC

set -e

CERT_DIR="${1:-./certs}"
DAYS=365
CA_SUBJECT="/C=ES/ST=Madrid/L=Madrid/O=AISAC/OU=Security/CN=AISAC CA"
SERVER_SUBJECT="/C=ES/ST=Madrid/L=Madrid/O=AISAC/OU=Security/CN=aisac-server"
AGENT_SUBJECT="/C=ES/ST=Madrid/L=Madrid/O=AISAC/OU=Security/CN=aisac-agent"

echo "Creating certificate directory: $CERT_DIR"
mkdir -p "$CERT_DIR"

# Generate CA private key
echo "Generating CA private key..."
openssl genrsa -out "$CERT_DIR/ca.key" 4096

# Generate CA certificate
echo "Generating CA certificate..."
openssl req -new -x509 -days $DAYS -key "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" -subj "$CA_SUBJECT"

# Generate server private key
echo "Generating server private key..."
openssl genrsa -out "$CERT_DIR/server.key" 2048

# Generate server CSR
echo "Generating server CSR..."
openssl req -new -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" -subj "$SERVER_SUBJECT"

# Create server certificate extensions file
cat > "$CERT_DIR/server.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = aisac-server
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate server certificate
echo "Generating server certificate..."
openssl x509 -req -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -out "$CERT_DIR/server.crt" -days $DAYS \
    -extfile "$CERT_DIR/server.ext"

# Generate agent private key
echo "Generating agent private key..."
openssl genrsa -out "$CERT_DIR/agent.key" 2048

# Generate agent CSR
echo "Generating agent CSR..."
openssl req -new -key "$CERT_DIR/agent.key" \
    -out "$CERT_DIR/agent.csr" -subj "$AGENT_SUBJECT"

# Create agent certificate extensions file
cat > "$CERT_DIR/agent.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

# Generate agent certificate
echo "Generating agent certificate..."
openssl x509 -req -in "$CERT_DIR/agent.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -out "$CERT_DIR/agent.crt" -days $DAYS \
    -extfile "$CERT_DIR/agent.ext"

# Clean up CSR and extension files
rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/*.ext "$CERT_DIR"/*.srl

# Set permissions
chmod 600 "$CERT_DIR"/*.key
chmod 644 "$CERT_DIR"/*.crt

echo ""
echo "Certificates generated in $CERT_DIR:"
echo "  - ca.crt      (CA certificate)"
echo "  - ca.key      (CA private key - keep secure!)"
echo "  - server.crt  (Server certificate)"
echo "  - server.key  (Server private key)"
echo "  - agent.crt   (Agent certificate)"
echo "  - agent.key   (Agent private key)"
echo ""
echo "To verify certificates:"
echo "  openssl verify -CAfile $CERT_DIR/ca.crt $CERT_DIR/server.crt"
echo "  openssl verify -CAfile $CERT_DIR/ca.crt $CERT_DIR/agent.crt"
