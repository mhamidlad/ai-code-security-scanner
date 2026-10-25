/** Vulnerable JavaScript code — for scanner testing and demonstration. */

const express = require('express');
const { exec, execSync } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');

const app = express();

// JS001: SQL Injection
function getUser(email) {
    const query = `SELECT * FROM users WHERE email = '${email}'`;
    db.query(query, (err, results) => {
        return results;
    });
}

function getUserById(id) {
    db.query("SELECT * FROM users WHERE id = " + req.params.id);
}

// JS002: Command Injection
function pingHost(host) {
    exec(`ping ${host}`);
}

function runCommand(userInput) {
    execSync(`echo ${userInput}`);
}

function runSpawn(userInput) {
    child_process.spawn(userInput);
}

// JS003: Hardcoded Secrets
const apiKey = "FAKE_LIVE_KEY_1234567890abcdefghijklmnopqrstuv";
const awsSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const password = "MySecretPassword123";
const githubToken = "FAKE_GITHUB_TOKEN_1234567890abcdefghijklmnopqrstuvwxyz1234567890";
const secretToken = "tok_1234567890abcdefghijklmnopqrstuv";

// JS004: XSS
function renderContent(content) {
    document.getElementById('output').innerHTML = req.body.content;
}

function writePage() {
    document.write(req.query.html);
}

function renderTemplate(name) {
    element.innerHTML = `Welcome ${name}`;
}

// JS005: SSRF
function fetchUrl() {
    fetch(req.query.url);
}

function getData() {
    axios.get(req.body.api_url);
}

// JS006: Path Traversal
function readFile(filename) {
    return fs.readFileSync(req.params.file);
}

function writeFile(path, content) {
    fs.writeFile(path, content);
}

function getUploadPath(userInput) {
    return path.join('/uploads', userInput);
}

// JS007: Unsafe Deserialization
function evaluateExpression() {
    eval(req.body.expression);
}

function runCode() {
    new Function(req.body.code)();
}

// JS008: Weak Crypto
function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

function hashSha1(data) {
    return crypto.createHash('sha1').update(data).digest('hex');
}

// JS009: NoSQL Injection
function findUser() {
    db.users.findOne({ email: req.body.email });
}

function findUsers() {
    db.users.find({ $where: req.body.query });
}
