import { app, BrowserWindow, ipcMain } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';
import sqlite3 from 'sqlite3';
import { spawn } from 'child_process';
import { WebSocketServer } from 'ws'; // Correct import
import { initDb } from './initDatabase.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let mainWindow;
let wss; // WebSocket server

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

app.whenReady().then(() => {
    console.log('App is ready');
    initDb();
    createWindow();
    runPythonScript();
    startWebSocketServer();
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

// SQLite Database Setup
const dbPath = path.join(__dirname, 'network_traffic.db');
const db = new sqlite3.Database(dbPath);

ipcMain.handle('fetch-firewall-stats', async (event) => {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            db.get('SELECT COUNT(*) AS totalPackets, SUM(malicious) AS maliciousPackets FROM firewall_logs', [], (err, row) => {
                if (err) {
                    console.error('Database error:', err);
                    reject(err);
                    return;
                }

                const stats = {
                    totalPackets: row.totalPackets,
                    maliciousPackets: row.maliciousPackets,
                    topSourceIPs: [],
                    topDestinationIPs: [],
                    protocolDistribution: [],
                };

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
    console.log('Fetching notification by ID:', id); // Add logging here
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
                console.log('Fetched row:', { notification, packetDetails }); // Add logging here
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
      SELECT id, src_ip, dst_ip, protocol, malicious, confidence, timestamp
      FROM firewall_logs
      ${searchCondition}
      ORDER BY id DESC
      LIMIT ${pageSize} OFFSET ${offset}
    `;

    const countQuery = `
      SELECT COUNT(*) as total
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
                    INSERT INTO securityactions (automaticThreatResponse, selectedOption, isActive, updateTime)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                `, [action.automaticThreatResponse, action.selectedOption, 1], function (insertErr) {
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
        db.get('SELECT automaticThreatResponse, selectedOption FROM securityactions WHERE isActive = 1', [], (err, row) => {
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
