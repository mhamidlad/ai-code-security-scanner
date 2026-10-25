/** Secure JavaScript code — demonstrates proper security practices. */

const express = require('express');
const { execFile } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const DOMPurify = require('isomorphic-dompurify');

const app = express();

// JS001: Secure SQL — parameterized queries
function getUser(email) {
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        return results;
    });
}

function getUserById(id) {
    db.query('SELECT * FROM users WHERE id = ?', [id]);
}

// JS002: Secure command execution — execFile with array
function pingHost(host) {
    execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
        return stdout;
    });
}

// JS003: Secrets in environment variables
const apiKey = process.env.API_KEY;
const awsSecretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
const dbUrl = process.env.DATABASE_URL;

// JS004: XSS prevention — textContent / sanitized HTML
function renderContent(content) {
    const clean = DOMPurify.sanitize(content);
    document.getElementById('output').textContent = clean;
}

// JS005: SSRF prevention — allowlist
const ALLOWED_HOSTS = new Set(['api.example.com', 'cdn.example.com']);

function fetchUrl(url) {
    const parsed = new URL(url);
    if (!ALLOWED_HOSTS.has(parsed.hostname)) {
        throw new Error('Host not allowed');
    }
    return fetch(url, { timeout: 5000 });
}

// JS006: Secure file access
const ALLOWED_DIR = require('path').resolve('/uploads');

function readFile(filename) {
    const filepath = require('path').resolve(ALLOWED_DIR, filename);
    if (!filepath.startsWith(ALLOWED_DIR)) {
        throw new Error('Path traversal detected');
    }
    return fs.readFileSync(filepath);
}

// JS007: Safe deserialization — JSON.parse
function parseData(data) {
    return JSON.parse(data);
}

// JS008: Secure password hashing
function hashPassword(password) {
    const salt = bcrypt.genSaltSync(12);
    return bcrypt.hashSync(password, salt);
}

function hashData(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

// JS009: Safe MongoDB query
function findUser(email) {
    // Sanitize input — no $ operators
    const sanitized = String(email).replace(/[${}]/g, '');
    db.users.findOne({ email: sanitized });
}
