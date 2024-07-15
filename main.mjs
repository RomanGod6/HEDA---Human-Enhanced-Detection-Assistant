import express from 'express';
import bodyParser from 'body-parser';
import { v4 as uuidv4 } from 'uuid';
import { app, BrowserWindow, ipcMain } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';
import sqlite3 from 'sqlite3';
import { spawn } from 'child_process';
import { WebSocketServer } from 'ws';
import { initDb } from './initDatabase.mjs';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let mainWindow;
let wss;

let BEARER_TOKEN = 'aaeedfflgsdjfgn;sdjfnb;jnfdnb;kjnfd;bjsdfjb'; // Default token

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            enableRemoteModule: false,
            nodeIntegration: false,
        },
    });

    mainWindow.loadURL('http://localhost:5173/');
    mainWindow.webContents.openDevTools();
}

function logToFile(message) {
    const logFilePath = path.join(__dirname, 'server.log');
    const logMessage = `${new Date().toISOString()} - ${message}\n`;
    fs.appendFile(logFilePath, logMessage, (err) => {
        if (err) {
            console.error('Error writing to log file', err);
        }
    });
}

function runPythonScript() {
    const pythonProcess = spawn('python', ['./Python/main.py']);

    pythonProcess.stdout.on('data', (data) => {
        console.log(`stdout: ${data}`);
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error(`stderr: ${data}`);
    });

    pythonProcess.on('close', (code) => {
        console.log(`Python script exited with code ${code}`);
    });
}

function startWebSocketServer() {
    wss = new WebSocketServer({ port: 8765 });

    wss.on('connection', (ws) => {
        console.log('WebSocket connection established');
        ws.on('message', (message) => {
            const data = JSON.parse(message);
            if (data.type === 'malicious_packet') {
                console.log('Malicious packet detected:', data);
                mainWindow.webContents.send('malicious_packet', data);
            }
        });
    });

    console.log('WebSocket server started on ws://localhost:8765');
}

ipcMain.handle('updateSettings', async (event, settings) => {
    if (settings.bearerToken) {
        BEARER_TOKEN = settings.bearerToken;
    }
});

app.whenReady().then(() => {
    console.log('App is ready');
    initDb();
    createWindow();
    runPythonScript();
    startWebSocketServer();
    startApiServer();
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        console.log('All windows closed');
        app.quit();
    }
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        console.log('Activating window');
        createWindow();
    }
});

const dbPath = path.join(__dirname, 'network_traffic.db');
const db = new sqlite3.Database(dbPath);

ipcMain.handle('fetch-firewall-stats', async (event) => {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            db.all('SELECT src_ip, dst_ip, COUNT(*) AS totalPackets, SUM(malicious) AS maliciousPackets FROM firewall_logs GROUP BY src_ip, dst_ip', [], (err, rows) => {
                if (err) {
                    console.error('Database error:', err);
                    reject(err);
                    return;
                }

                const stats = {
                    totalPackets: 0,
                    maliciousPackets: 0,
                    topSourceIPs: [],
                    topDestinationIPs: [],
                    protocolDistribution: [],
                };

                rows.forEach(row => {
                    stats.totalPackets += row.totalPackets;
                    stats.maliciousPackets += row.maliciousPackets;
                });

                db.all('SELECT src_ip AS ip, COUNT(*) AS count FROM firewall_logs GROUP BY src_ip ORDER BY count DESC LIMIT 10', [], (err, rows) => {
                    if (err) {
                        console.error('Database error:', err);
                        reject(err);
                        return;
                    }
                    stats.topSourceIPs = rows;

                    db.all('SELECT dst_ip AS ip, COUNT(*) AS count FROM firewall_logs GROUP BY dst_ip ORDER BY count DESC LIMIT 10', [], (err, rows) => {
                        if (err) {
                            console.error('Database error:', err);
                            reject(err);
                            return;
                        }
                        stats.topDestinationIPs = rows;

                        db.all('SELECT protocol, COUNT(*) AS count FROM firewall_logs GROUP BY protocol', [], (err, rows) => {
                            if (err) {
                                console.error('Database error:', err);
                                reject(err);
                                return;
                            }
                            stats.protocolDistribution = rows;

                            resolve(stats);
                        });
                    });
                });
            });
        });
    });
});


ipcMain.handle('fetch-notifications', async (event) => {
    return new Promise((resolve, reject) => {
        db.all('SELECT * FROM notifications WHERE notified = 1 AND acknowledged = 0', [], (err, rows) => {
            if (err) {
                console.error('Database error:', err);
                reject(err);
                return;
            }
            resolve(rows);
        });
    });
});

ipcMain.handle('fetch-notification-by-id', async (event, id) => {
    console.log('Fetching notification by ID:', id);
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM notifications WHERE log_id = ?', [id], (err, notification) => {
            if (err) {
                console.error('Database error:', err);
                reject(err);
                return;
            }
            if (!notification) {
                resolve(null);
                return;
            }
            db.get('SELECT * FROM firewall_logs WHERE id = ?', [notification.log_id], (err, packetDetails) => {
                if (err) {
                    console.error('Database error:', err);
                    reject(err);
                    return;
                }
                console.log('Fetched row:', { notification, packetDetails });
                resolve({ notification, packetDetails });
            });
        });
    });
});

ipcMain.handle('update-notification-status', async (event, id, isMalicious) => {
    return new Promise((resolve, reject) => {
        db.run('UPDATE notifications SET acknowledged = 1, malicious = ? WHERE log_id = ?', [isMalicious, id], function (err) {
            if (err) {
                console.error('Database error:', err);
                reject(err);
                return;
            }
            resolve({ success: true });
        });
    });
});

ipcMain.handle('fetch-packet-logs', async (event, { page, pageSize, search, searchColumns }) => {
    const offset = (page - 1) * pageSize;
    const searchCondition = search ? `WHERE ${searchColumns.map(col => `${col} LIKE '%${search}%'`).join(' OR ')}` : '';

    const logsQuery = `
      SELECT src_ip, dst_ip, protocol, COUNT(*) AS packetCount, SUM(malicious) AS maliciousPackets, MIN(timestamp) AS firstSeen, MAX(timestamp) AS lastSeen
      FROM firewall_logs
      ${searchCondition}
      GROUP BY src_ip, dst_ip, protocol
      ORDER BY lastSeen DESC
      LIMIT ${pageSize} OFFSET ${offset}
    `;

    const countQuery = `
      SELECT COUNT(DISTINCT src_ip, dst_ip, protocol) as total
      FROM firewall_logs
      ${searchCondition}
    `;

    const logs = await new Promise((resolve, reject) => {
        db.all(logsQuery, [], (err, rows) => {
            if (err) {
                reject(err);
            } else {
                resolve(rows);
            }
        });
    });

    const total = await new Promise((resolve, reject) => {
        db.get(countQuery, [], (err, row) => {
            if (err) {
                reject(err);
            } else {
                resolve(row.total);
            }
        });
    });

    return { logs, total };
});


ipcMain.handle('fetch-security-actions', (event) => {
    return new Promise((resolve, reject) => {
        db.all('SELECT * FROM securityactions ORDER BY updateTime DESC', (err, rows) => {
            if (err) {
                reject(err);
                return;
            }
            resolve(rows);
        });
    });
});

ipcMain.handle('save-security-action', (event, action) => {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            db.run('UPDATE securityactions SET isActive = 0 WHERE isActive = 1', (updateErr) => {
                if (updateErr) {
                    reject(updateErr);
                    return;
                }
                db.run(`
                    INSERT INTO securityactions (automaticThreatResponse, selectedOption, bearerToken, isActive, updateTime)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                `, [action.automaticThreatResponse, action.selectedOption, action.bearerToken, 1], function (insertErr) {
                    if (insertErr) {
                        reject(insertErr);
                        return;
                    }
                    resolve({ id: this.lastID });
                });
            });
        });
    });
});


ipcMain.handle('fetch-settings', async (event) => {
    return new Promise((resolve, reject) => {
        db.get('SELECT automaticThreatResponse, selectedOption, bearerToken FROM securityactions WHERE isActive = 1', [], (err, row) => {
            if (err) {
                console.error('Database error:', err);
                reject(err);
                return;
            }
            resolve(row);
        });
    });
});


ipcMain.handle('fetch-whitelist', async (event) => {
    return new Promise((resolve, reject) => {
        db.all('SELECT * FROM whitelist', [], (err, rows) => {
            if (err) {
                console.error('Database error:', err);
                reject(err);
            } else {
                resolve(rows);
            }
        });
    });
});

ipcMain.handle('add-to-whitelist', async (event, ipAddress) => {
    return new Promise((resolve, reject) => {
        db.run('INSERT INTO whitelist (ip_address) VALUES (?)', [ipAddress], function (err) {
            if (err) {
                console.error('Database error:', err);
                reject(err);
            } else {
                resolve({ id: this.lastID, ip_address: ipAddress });
            }
        });
    });
});

ipcMain.handle('remove-from-whitelist', async (event, id) => {
    return new Promise((resolve, reject) => {
        db.run('DELETE FROM whitelist WHERE id = ?', [id], function (err) {
            if (err) {
                console.error('Database error:', err);
                reject(err);
            } else {
                resolve({ success: true });
            }
        });
    });
});

ipcMain.handle('mark-all-notifications-as-viewed', async (event) => {
    return new Promise((resolve, reject) => {
        db.run('UPDATE notifications SET acknowledged = 1 WHERE acknowledged = 0', function (err) {
            if (err) {
                console.error('Database error:', err);
                reject(err);
                return;
            }
            resolve({ success: true });
        });
    });
});


function startApiServer() {
    const apiApp = express();
    apiApp.use(bodyParser.json());

    apiApp.use((req, res, next) => {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        if (!token) {
            logToFile('Unauthorized access attempt');
            return res.sendStatus(401);
        }

        if (token !== BEARER_TOKEN) {
            logToFile(`Forbidden access with token: ${token}`);
            // Notify via Java program
            const javaProcess = spawn('java', ['Notify', token]);
            javaProcess.stdout.on('data', (data) => {
                const message = `Java stdout: ${data}`;
                console.log(message);
                logToFile(message);
            });

            javaProcess.stderr.on('data', (data) => {
                const message = `Java stderr: ${data}`;
                console.error(message);
                logToFile(message);
            });

            return res.sendStatus(403);
        }
        next();
    });

    apiApp.post('/api/alerts', (req, res) => {
        const { source, timestamp, alertType, severity, details } = req.body;
        const { src_ip, dst_ip, filename } = details;

        const log_id = saveAlertToDatabase(source, timestamp, alertType, severity, src_ip, dst_ip, filename);
        res.json({ success: true, log_id });
    });

    apiApp.get('/api/firewall-logs', (req, res) => {
        db.all('SELECT * FROM firewall_logs', [], (err, rows) => {
            if (err) {
                res.status(500).json({ error: 'Database error' });
                return;
            }
            res.json({ logs: rows });
        });
    });

    apiApp.get('/api/notifications', (req, res) => {
        db.all('SELECT * FROM notifications', [], (err, rows) => {
            if (err) {
                res.status(500).json({ error: 'Database error' });
                return;
            }
            res.json({ notifications: rows });
        });
    });

    apiApp.listen(3000, () => {
        console.log('API server started on port 3000');
    });
}

function saveAlertToDatabase(source, timestamp, alertType, severity, src_ip, dst_ip, filename) {
    return new Promise((resolve, reject) => {
        db.run('INSERT INTO alerts (source, timestamp, alertType, severity, src_ip, dst_ip, filename) VALUES (?, ?, ?, ?, ?, ?, ?)', [source, timestamp, alertType, severity, src_ip, dst_ip, filename], function (err) {
            if (err) {
                console.error('Database error:', err);
                reject(err);
            } else {
                resolve(this.lastID);
            }
        });
    });
}
