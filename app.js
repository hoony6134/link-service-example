const express = require('express');
const { Client } = require('pg');
const cors = require('cors');
const useragent = require('express-useragent');
const requestIp = require('request-ip');
const favicon = require('serve-favicon');
const { sql, db } = require('@vercel/postgres'); // Import the Vercel Postgres SDK
const env = require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000; // Use environment variable for port

// Get database URL from environment variable
const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
    console.error("DATABASE_URL environment variable is missing. Please set it.");
    process.exit(1);
}

// Create a Postgres client
const client = new Client({
    connectionString: databaseUrl,
    ssl: {
        rejectUnauthorized: false
    }
});

const adminList = [
    { 'login': 'admin', 'password': process.env.ADMIN1_PASSWORD },
    { 'login': 'admin2', 'password': process.env.ADMIN2_PASSWORD }
];

app.use(cors());
app.use(express.json());
app.use(useragent.express());
app.use(favicon(__dirname + '/favicon.ico'));

// Basic Authentication Middleware
const authenticate = async (req, res, next) => {
    const b64auth = (req.headers.authorization || '').split(' ')[1] || '';
    const [login, password] = Buffer.from(b64auth, 'base64').toString().split(':');
    if (!login || !password || !adminList.some(admin => admin.login === login && admin.password === password)) {
        res.set('WWW-Authenticate', 'Basic realm="401"');
        res.status(401).send('관리자 권한이 필요합니다.');
        return;
    }
    next(); // Proceed if authenticated
};

// Connect to the database
(async () => {
    try {
        await client.connect();
        console.log('Connected to PostgreSQL!');
    } catch (err) {
        console.error('Connection error', err.stack);
    }
})();

// Route for the main page 
app.get('/', authenticate, (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

// Route for ping
app.get('/ping', (req, res) => {
    res.send('pong!');
});

// Route for logs (with authentication)
app.get('/logs', authenticate, async (req, res) => {
    try {
        const result = await client.query('SELECT * FROM logs'); // Use client.query for Postgres
        res.send(`
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
            <style>
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th, td {
                border: 1px solid black;
                padding: 8px;
                text-align: center;
            }
            th {
                background-color: #f2f2f2;
            }

            a {
                text-decoration: none;
                color: #3322bb;
            }
            </style>
            <h1>Logs</h1>
            <a href="/" style="padding-bottom: 1rem;"><i class="bi bi-chevron-left" style="margin-right: 0.2rem;"></i>홈으로</a>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Alias</th>
                        <th>IP Address</th>
                        <th>User Agent</th>
                        <th>Visit Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    ${result.rows.map(log => `
                        <tr>
                            <td>${log.id}</td>
                            <td><a href="/logs/${log.alias}">${log.alias}</a></td>
                            <td>${log.ip}</td>
                            <td>${log.useragent}</td>
                            <td>${log.timestamp}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `);
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});

// Route for logs with alias (with authentication)
app.get('/logs/:alias', authenticate, async (req, res) => {
    try {
        const { alias } = req.params;
        // Parameterized query to prevent SQL injection
        const result = await client.query('SELECT * FROM logs WHERE alias = $1', [alias]);
        res.send(`
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
            <style>
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th, td {
                border: 1px solid black;
                padding: 8px;
                text-align: center;
            }
            th {
                background-color: #f2f2f2;
            }

            a {
                text-decoration: none;
                color: #3322bb;
            }
            </style>
            <h1>Logs</h1>
            <a href="/logs" style="padding-bottom: 1rem;"><i class="bi bi-chevron-left" style="margin-right: 0.2rem;"></i>로그 목록</a>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Alias</th>
                        <th>IP Address</th>
                        <th>User Agent</th>
                        <th>Visit Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    ${result.rows.map(log => `
                        <tr>
                            <td>${log.id}</td>
                            <td><a href="/${log.alias}">${log.alias}</a></td>
                            <td>${log.ip}</td>
                            <td>${log.useragent}</td>
                            <td>${log.timestamp}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `);
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});

// Route for the link list (with authentication)
app.get('/list', authenticate, async (req, res) => {
    try {
        const result = await client.query('SELECT * FROM links'); // Use client.query for Postgres
        res.send(`
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
            <style>
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th, td {
                border: 1px solid black;
                padding: 8px;
                text-align: center;
            }
            th {
                background-color: #f2f2f2;
            }

            a {
                text-decoration: none;
                color: #3322bb;
            }
            </style>
            <h1>Links</h1>
            <a href="/" style="padding-bottom: 1rem;"><i class="bi bi-chevron-left" style="margin-right: 0.2rem;"></i>홈으로</a>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Alias</th>
                        <th style="max-width: 200px;">URL</th>
                        <th>iOS URL</th>
                        <th>Android URL</th>
                        <th>Status</th>
                        <th>Password</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${result.rows.map(link => `
                        <tr>
                            <td>${link.id}</td>
                            <td><a href="/${link.alias}">${link.alias}</a></td>
                            <td style="max-width: 400px; word-wrap: break-word;">${link.url}</td>
                            <td>${link.ios_url}</td>
                            <td>${link.android_url}</td>
                            <td>
                                ${link.status === 1 ? '<i class="bi bi-globe" title="Public"></i>' : ''}
                                ${link.status === 2 ? '<i class="bi bi-eye-slash" title="Protected"></i>' : ''}
                                ${link.status === 3 ? '<i class="bi bi-lock" title="Private"></i>' : ''}
                            </td>
                            <td>${link.password}</td>
                            <td>
                                <a href="/edit/${link.alias}"><i class="bi bi-pencil" title="Edit" style="margin-right: 0.5rem; color: #3399bb;"></i></a>
                                <a href="/delete/${link.id}"><i class="bi bi-trash" title="Delete" style="color: #bb3333;"></i></a>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `);
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});

// Route for deleting a link (with authentication)
app.get('/delete/:id', authenticate, async (req, res) => {
    try {
        const { id } = req.params;
        const ADMIN_KEY = process.env.ADMIN_KEY;
        // Parameterized query to prevent SQL injection
        const result = await client.query('SELECT * FROM links WHERE id = $1', [id]);
        res.send(`
            <style>
            button {
                padding: 0.5rem 1rem;
                border: none;
                border-radius: 4px;
                background-color: #dc3545;
                color: #fff;
                cursor: pointer;
            }
            button:hover {
                background-color: #c82333;
            }
            </style>
            <h1>Link를 삭제하시겠습니까?</h1>
            <p>Alias: ${result.rows[0].alias}</p>
            <p>URL: ${result.rows[0].url}</p>
            <button id="deletebutton">
                <span>삭제</span>
            </button>
            <script>
                const deleteButton = document.getElementById('deletebutton');
                deleteButton.addEventListener('click', async () => {
                    const response = await fetch('/delete/${id}', {
                        method: 'DELETE',
                        headers: {
                            'Authorization': '${ADMIN_KEY}'
                        }
                    });
                    const result = await response.json();
                    alert(result.message);
                    window.location.href = '/list';
                });
            </script>
        `);
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});

// Route to handle link deletion (with authentication)
app.delete('/delete/:id', authenticate, async (req, res) => {
    try {
        const { id } = req.params;
        const password = process.env.ADMIN_KEY;
        const authKey = req.headers.authorization;
        if (!authKey || authKey !== password) {
            res.status(401).send('관리자 권한이 필요합니다.');
            return;
        }
        // Parameterized query to prevent SQL injection
        await client.query('DELETE FROM links WHERE id = $1', [id]);
        res.status(200).send({ success: true, message: 'Link 삭제 성공' });
    } catch (err) {
        console.error(err);
        res.status(500).send({ success: false, message: 'Internal Server Error' });
    }
});

// Route for creating a new link (with authentication)
app.get('/create', authenticate, (req, res) => {
    res.sendFile(__dirname + '/create.html');
});

// Route to check if alias is available (with authentication)
app.get('/checkalias/:alias', authenticate, async (req, res) => {
    try {
        const { alias } = req.params;
        // Parameterized query to prevent SQL injection
        const result = await client.query('SELECT * FROM links WHERE alias = $1', [alias]);
        if (result.rows.length === 0) {
            res.status(200).send({ success: true, message: 'Alias 사용 가능' });
        } else {
            res.status(409).send({ success: false, message: '이미 사용중인 링크입니다.' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});

// Route to handle link creation (with authentication)
app.post('/create', authenticate, async (req, res) => {
    try {
        const password = process.env.ADMIN_KEY;
        const authKey = req.body.authKey;
        if (!authKey || authKey !== password) {
            res.status(401).send('관리자 권한이 필요합니다.');
            return;
        }
        const { name, alias, url, ios_url, android_url, status, password: set_pass } = req.body;

        // Check if alias already exists using parameterized query
        const checkQuery = 'SELECT * FROM links WHERE alias = $1';
        const checkResult = await db.query(checkQuery, [alias]);

        if (checkResult.rows.length > 0) {
            res.status(409).send({ success: false, message: '이미 사용중인 링크입니다.' });
            return;
        }

        // Insert new link using parameterized query to prevent SQL injection
        const insertQuery = `
            INSERT INTO links (alias, url, name, ios_url, android_url, status, password) 
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        `;
        await client.query(insertQuery, [alias, url, name, ios_url, android_url, status, set_pass]);
        res.status(200).send({ success: true, message: 'Link 생성 성공' });
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});

// Route for editing a link (with authentication)
app.get('/edit/:alias', authenticate, async (req, res) => {
    try {
        const { alias } = req.params;
        const ADMIN_KEY = process.env.ADMIN_KEY;
        // Parameterized query to prevent SQL injection
        const result = await client.query('SELECT * FROM links WHERE alias = $1', [alias]);
        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>${process.env.SERVICE_NAME} Link 편집 | ${process.env.SERVICE_NAME} Link Service</title>
                <link rel="stylesheet" as="style" crossorigin href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/static/pretendard-dynamic-subset.min.css" />
                <style>
                body {
                    font-family: 'Pretendard';
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                    font-family: Arial, sans-serif;
                    background-color: #f5f5f5;
                }
        
                h1 {
                    font-family: 'Pretendard';
                    font-size: 4rem;
                    margin-bottom: 1rem;
                    color: #333;
                }
        
                p {
                    font-family: 'Pretendard';
                    font-size: 1.5rem;
                    color: #666;
                }
        
                form {
                    font-family: 'Pretendard';
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    margin-top: 2rem;
                }
        
                input {
                    font-family: 'Pretendard';
                    padding: 0.5rem;
                    margin-bottom: 1rem;
                    border: 1px solid #ccc;
                    border-radius: 4px;
                    width: 100%;
                    max-width: 500px;
                }
        
                button {
                    font-family: 'Pretendard';
                    padding: 0.5rem 1rem;
                    border: none;
                    border-radius: 4px;
                    background-color: #007bff;
                    color: #fff;
                    cursor: pointer;
                }
        
                button:hover {
                    font-family: 'Pretendard';
                    background-color: #0056b3;
                }
        
                select {
                    font-family: 'Pretendard';
                    padding: 0.5rem;
                    margin-bottom: 1rem;
                    border: 1px solid #ccc;
                    border-radius: 4px;
                    width: 100%;
                    max-width: 500px;
                }
                </style>
            </head>
            <body>
                <style>
                @media (max-width: 768px) {
                    h1 {
                        font-size: 3rem;
                    }
                }
                </style>
                <h1>Link 편집</h1>
                <img src="https://i.imgur.com/U77qqOC.png" alt="Link Services" width="120" height="120" style="margin-bottom:1.5rem;">
                <form>
                    ${result.rows.map(link => `
                    <input type="text" name="name" placeholder="링크 제목" value="${link.name}">
                    <input type="text" name="alias" placeholder="연결될 alias" value="${link.alias}" readonly>
                    <input type="text" name="url" placeholder="URL" value="${link.url}">
                    <select name="status" title="Status" value="${link.status}">
                        <option value="1">Public</option>
                        <option value="2">Protected</option>
                        <option value="3">Private</option>
                    </select>
                    <input type="text" name="password" placeholder="Password" hidden value="${link.password}">
                    <input type="text" name="ios_url" placeholder="iOS URL" value="${link.ios_url}">
                    <input type="text" name="android_url" placeholder="Android URL" value="${link.android_url}">
                    <button type="submit">링크 편집</button>
                    `).join('')}
                </form>
                <script>
                const form = document.querySelector('form');
                const inputs = form.querySelectorAll('input');
                const select = form.querySelector('select');
                const button = form.querySelector('button');
        
                select.addEventListener('change', () => {
                    const selected = select.value;
                    const password = form.querySelector('input[name="password"]');
                    if (selected === '2') {
                        password.removeAttribute('hidden');
                    } else {
                        password.setAttribute('hidden', true);
                    }
                });
        
                form.addEventListener('submit', async event => {
                    event.preventDefault();
                    const data = {
                        name: inputs[0].value,
                        alias: inputs[1].value,
                        url: inputs[2].value,
                        status: select.value,
                        password: inputs[3].value,
                        ios_url: inputs[4].value,
                        android_url: inputs[5].value,
                        authKey: '${ADMIN_KEY}'
                    }
                    console.log(data);
                    const response = await fetch('/edit', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(data)
                    });
                    const result = await response.json();
                    alert(result.message);
                    form.reset();
                    history.back();
                });
                </script>
            </body>
            </html>
        `);
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});

// Route to handle link editing (with authentication)
app.post('/edit', authenticate, async (req, res) => {
    try {
        const password = process.env.ADMIN_KEY; // Replace with your actual admin key
        const authKey = req.body.authKey;
        if (!authKey || authKey !== password) {
            res.status(401).send('관리자 권한이 필요합니다.');
            return;
        }
        const { name, alias, url, ios_url, android_url, status, password: set_pass } = req.body;
        // Parameterized query to prevent SQL injection
        await client.query(
            'UPDATE links SET name = $1, url = $2, ios_url = $3, android_url = $4, status = $5, password = $6 WHERE alias = $7',
            [name, url, ios_url, android_url, status, set_pass, alias]
        );
        res.status(200).send({ success: true, message: 'Link 수정 성공' });
    } catch (err) {
        console.error(err);
        res.status(500).send({ success: false, message: 'Internal Server Error' });
    }
});

// Catch-all route for handling link redirection
app.get('*', async (req, res) => {
    try {
        const ua = req.useragent;
        const destination = req.originalUrl.slice(1).split('?')[0];
        // Parameterized query to prevent SQL injection
        const result = await client.query('SELECT * FROM links WHERE alias = $1', [destination]);

        if (result.rows.length === 0) {
            res.sendFile(__dirname + '/404.html');
        } else {
            const status = result.rows[0].status;
            if (status === 1) {
                // Do nothing for public links
            } else if (status === 2) {
                const real_password = result.rows[0].password;
                const user_password = req.query.pw;
                if (real_password !== user_password) {
                    res.status(403).send('Forbidden');
                    return;
                }
            } else if (status === 3) {
                const auth = { login: 'admin', password: 'merona06*' };
                const b64auth = (req.headers.authorization || '').split(' ')[1] || '';
                const [login, password] = Buffer.from(b64auth, 'base64').toString().split(':');
                if (!login || !password || login !== auth.login || password !== auth.password) {
                    res.set('WWW-Authenticate', 'Basic realm="401"');
                    res.status(401).send('관리자 권한이 필요합니다.');
                    return;
                }
            }

            const isIOS = ua.isiPhone || ua.isiPad || ua.isiPod;
            const isAndroid = ua.isAndroid;
            const ip = requestIp.getClientIp(req);

            // Parameterized query to prevent SQL injection
            await client.query('INSERT INTO logs (alias, ip, useragent) VALUES ($1, $2, $3)', [destination, ip, req.headers['user-agent']]);

            if (isIOS) {
                res.redirect(result.rows[0].ios_url || result.rows[0].url);
            } else if (isAndroid) {
                res.redirect(result.rows[0].android_url || result.rows[0].url);
            } else {
                res.redirect(result.rows[0].url);
            }
        }
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});

// Start the server
app.listen(port, '0.0.0.0', () => {
    console.log(`Server is running on ${port}`);
});

module.exports = app;