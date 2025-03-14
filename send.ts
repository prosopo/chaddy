import net from "net";

const payloads: {
    [key: string]: number[];
} = {
    "valid": [
        0x16, 0x03, 0x01, 0x00, 0x8f, // TLS Record Header (Handshake, TLS 1.0, Length 143)
        0x01, 0x00, 0x00, 0x8b, // Handshake: ClientHello
        0x03, 0x03, // TLS 1.2
        0x5e, 0x3c, 0x92, 0x34, 0x0f, 0xa3, 0x1f, 0xaf, // Random bytes
        0xd1, 0x41, 0x8b, 0x12, 0x4c, 0x9d, 0x94, 0x00,
        0x00, // Session ID Length: 0 (No session resumption)
        0x00, 0x02, // Cipher Suites Length: 2 bytes
        0x00, 0x2f, // Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA
        0x01, // Compression Methods Length: 1
        0x00, // No Compression
        0x00, 0x28, // Extensions Length: 40 bytes
        0x00, 0x0d, // Extension: Signature Algorithms
        0x00, 0x04, 0x00, 0x02, 0x05, 0x01, // Signature: RSA+SHA1
        0x00, 0x33, // Extension: Custom (0x0033)
        0x00, 0x02, 0xde, 0xad, // Custom Data "DEAD"
    ],
    "3B": [
        0x16, 0x03, 0x01
    ],
    "empty": [],
    "1B": [0x16], // TLS Record Header only
    "notClientHello": [
        0x00 // not a tls handshake type
    ],
    "max": [0x16, 0x03, 0x01, 0xff, 0xff - 5, ...Array(Math.pow(2, 16) - 5).fill(0x00)],
    "overflow": [0x16, 0x03, 0x01, 0xff, 0xff, ...Array(99999).fill(0x00)],
}

// console.log('max len', payloads['max'].length);
const server = process.argv[2] || "";
const payload = payloads[process.argv[3] || ''];
if (!payload) {
    console.error("Invalid index");
    process.exit(1);
}

const buffer = Buffer.from(payload);

const client = new net.Socket();
const port = 443;

client.connect(port, server, () => {
    console.log("Connected, sending payload...");
    client.write(buffer); // Send raw TLS ClientHello
});

client.on("data", (data) => {
    console.log("Received:", data.toString("hex"));
    client.destroy();
});

client.on("error", (err) => {
    console.error("Connection error:", err);
});

client.on("close", () => {
    console.log("Connection closed.");
});
