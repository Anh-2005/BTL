const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const forge = require('node-forge');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Load static frontend files
app.use(express.static('public'));

// ====== 🔐 KHỞI TẠO CẶP KHÓA RSA 2048 BIT ======
let rsaKeypair = null;

forge.pki.rsa.generateKeyPair({ bits: 2048, workers: 2 }, (err, keypair) => {
    if (err) {
        console.error('❌ Lỗi tạo cặp khóa RSA:', err);
        process.exit(1);
    }
    rsaKeypair = keypair;
    console.log('✅ Đã tạo cặp khóa RSA 2048-bit');
    console.log('📤 Public Key PEM:\n', forge.pki.publicKeyToPem(keypair.publicKey));
    console.log('🔐 Private Key PEM:\n', forge.pki.privateKeyToPem(keypair.privateKey));
});

// ====== 🔗 SOCKET.IO ======
io.on('connection', (socket) => {
    console.log('🔌 Client connected');

    // Gửi public key cho client nếu yêu cầu
    socket.on('request_public_key', () => {
        if (rsaKeypair) {
            const pem = forge.pki.publicKeyToPem(rsaKeypair.publicKey);
            socket.emit('public_key', pem);
        }
    });

    // Nhận session key đã mã hóa từ client
    socket.on('session_key_encrypted', (data) => {
        if (!rsaKeypair) {
            console.error('❌ Cặp khóa RSA chưa sẵn sàng!');
            return;
        }

        const encryptedBase64 = data.encryptedSessionKey;

        try {
            // Giải mã RSA-OAEP (SHA-512)
            const encryptedBytes = forge.util.decode64(encryptedBase64);
            const decryptedSessionKey = rsaKeypair.privateKey.decrypt(encryptedBytes, 'RSA-OAEP', {
                md: forge.md.sha512.create(),
                mgf1: {
                    md: forge.md.sha512.create()
                }
            });

            console.log('✅ Đã giải mã session key:', decryptedSessionKey);
            socket.emit('session_key_decrypted', { sessionKey: decryptedSessionKey });

        } catch (e) {
            console.error('❌ Lỗi giải mã RSA-OAEP:', e.message);
        }
    });

    socket.on('ack_received', (data) => {
        console.log(`✅ ACK received from client: ${JSON.stringify(data)}`);
    });

    socket.on('disconnect', () => {
        console.log('❌ Client disconnected');
    });
});

// ====== SERVER START ======
const PORT = 3000;
server.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
});