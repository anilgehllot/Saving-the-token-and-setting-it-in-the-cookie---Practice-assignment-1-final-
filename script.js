const crypto = require("crypto");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const SECRET_KEY = process.env.JWT_SECRET || "supersecretkey";
const ENCRYPTION_KEY = crypto.scryptSync(process.env.ENCRYPTION_SECRET || "encryptionkey", "salt", 32);
const IV_LENGTH = 16; 

// Encrypt function: Generates JWT and encrypts it
const encrypt = (payload) => {
    try {
        // Generate JWT token
        const token = jwt.sign(payload, SECRET_KEY, { expiresIn: "1h" });

        // Generate IV
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);

        // Encrypt token
        let encrypted = cipher.update(token, "utf8", "hex");
        encrypted += cipher.final("hex");

        // Return IV + encrypted token as a single string
        return iv.toString("hex") + encrypted;
    } catch (error) {
        console.error("Encryption failed:", error);
        return null;
    }
};

// Decrypt function: Decrypts token and verifies JWT
const decrypt = (encryptedToken) => {
    try {
        // Extract IV and encrypted token
        const iv = Buffer.from(encryptedToken.slice(0, IV_LENGTH * 2), "hex");
        const encryptedText = encryptedToken.slice(IV_LENGTH * 2);

        const decipher = crypto.createDecipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);

        // Decrypt token
        let decrypted = decipher.update(encryptedText, "hex", "utf8");
        decrypted += decipher.final("utf8");

        // Verify JWT token
        return jwt.verify(decrypted, SECRET_KEY);
    } catch (error) {
        console.error("Decryption failed:", error);
        return null;
    }
};

module.exports = {
    encrypt,
    decrypt
};
Script.js