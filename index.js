const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const { promisify } = require('util');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const app = express();
const port = 3000;

app.use(session({
    secret: 'YooSfCXocuH01fPur6hjTpiZ2q9HWulrvxgDhgB+RpY=', 
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60 * 60 * 1000 } 
}));
app.use(express.static(path.join(__dirname, 'public'))); 
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(bodyParser.urlencoded({ extended: true }));

const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error('Ошибка подключения к базе данных:', err.message);
    } else {
        console.log('Подключение к базе данных успешно.');

        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullName TEXT NOT NULL,
            address TEXT NOT NULL,
            date TEXT NOT NULL,
            time TEXT NOT NULL,
            services TEXT NOT NULL,
            pay TEXT NOT NULL,
            status TEXT
        )`);
    }
});

const dbGet = promisify(db.get).bind(db);
const dbRun = promisify(db.run).bind(db);
const dbAll = promisify(db.all).bind(db);


app.get('/', (req, res) => res.redirect('/registration'));

app.get('/registration', (req, res) => {
    res.render('Registration', { pathToImage: '/images/index.jpg' }); 
});

app.get('/registration', (req, res) => {
    res.render('registration'); 
});

app.post('/registration', (req, res) => {
    const { username, email, password } = req.body;

    function dbRun(sql, params) {
        return new Promise((resolve, reject) => {
            db.run(sql, params, function(err) {
                if (err) {
                    return reject(err);
                }

                resolve({ lastID: this.lastID });
            });
        });
    }

    if (!username || !email || !password) {
        return res.status(400).send('Все поля должны быть заполнены.');
    }

    dbGet('SELECT * FROM users WHERE username = ? OR email = ?', [username, email])
        .then(row => {
            if (row) {
                return res.status(400).send('Имя пользователя или email уже используются.');
            }

            return bcrypt.hash(password, 10);
        })
        .then(hash => {
            return dbRun('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hash]);
        })
        .then(result => {
            console.log('Результат вставки:', result); 
            if (!result || !result.lastID) {
                throw new Error('Не удалось получить ID нового пользователя.');
            }
            
            console.log(`Пользователь ${username} добавлен с ID: ${result.lastID}`);
            
            req.session.user = { id: result.lastID, username: username };
            
            res.redirect('/login'); 
        })
        .catch(err => {
            console.error(err.message);
            return res.status(500).send('Ошибка сервера');
        });
});

app.get('/login', (req, res) => {
    res.render('Login'); 
});

function handleError(res, message, status = 500) {
    console.error(message);
    return res.status(status).json({ success: false, message });
}

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return handleError(res, 'Имя пользователя и пароль обязательны.', 400);
    }

    try {
        if (username === 'adminka' && password === 'password') {
            req.session.user = { id: 'admin', username: 'adminka' };
            return res.json({ success: true, redirect: '/admin' }); 
        }

        const row = await dbGet('SELECT * FROM users WHERE username = ?', [username]);
        if (!row) {
            return handleError(res, 'Неправильное имя пользователя или пароль.', 401);
        }

        const match = await bcrypt.compare(password, row.password);
        if (match) {
            req.session.user = { id: row.id, username: row.username };
            return res.json({ success: true, redirect: '/dashboard' }); 
        } else {
            return handleError(res, 'Неправильное имя пользователя или пароль.', 401);
        }
    } catch (err) {
        return handleError(res, 'Ошибка сервера');
    }
});

function ensureAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    }
    res.redirect('/login');
}

app.get('/dashboard', ensureAuthenticated, (req, res) => {
    res.render('Dashboard', { user: req.session.user });
});

app.get('/logout', (req, res) => {
    res.render('logout');
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Ошибка при выходе' });
        }
        res.redirect('/api/requests'); 
    });
});

app.get('/application', ensureAuthenticated, (req, res) => {
    res.render('application');
});

app.get('/admin', async (req, res) => {
    try {
        const rows = await db.all('SELECT * FROM requests');
        res.render('admin', { requests: rows });
    } catch (err) {
        console.error('Ошибка получения заявок:', err);
        res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
});

app.get('/api/requests', async (req, res) => {
    try {
        const rows = await dbAll('SELECT * FROM requests');
        if (!rows || rows.length === 0) {
            console.log('Нет заявок в базе данных.');
        } else {
            console.log('Полученные заявки:', rows);
        }
        res.json(rows);
    } catch (err) {
        console.error('Ошибка получения заявок:', err);
        res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
});

app.post('/api/requests', async (req, res) => {
    const { fullName, address, date, time, services, pay } = req.body;
    try {
        const result = await db.run('INSERT INTO requests (fullName, address, date, time, services, pay) VALUES (?, ?, ?, ?, ?, ?)', 
            [fullName, address, date, time, services, pay]);
        res.status(201).json({ success: true, id: result.lastID });
    } catch (err) {
        console.error('Ошибка добавления заявки:', err);
        res.status(500).json({ success: false, message: 'Ошибка добавления заявки' });
    }
});

app.put('/api/requests/:id/status', ensureAuthenticated, async (req, res) => {
    const id = req.params.id;
    const { status } = req.body; 

    try {
        const request = await db.get('SELECT * FROM requests WHERE id = ?', [id]);
        if (!request) {
            return res.status(404).json({ success: false, message: 'Заявка не найдена' });
        }

        await db.run('UPDATE requests SET status = ? WHERE id = ?', [status, id]);
        res.json({ success: true });
    } catch (err) {
        console.error('Ошибка обновления заявки:', err);
        res.status(500).json({ success: false, message: 'Ошибка обновления заявки' });
    }
});

app.put('/api/requests/:id/accept', ensureAuthenticated, async (req, res) => {
    const id = req.params.id;
    try {
        const request = await db.get('SELECT * FROM requests WHERE id = ?', [id]);
        if (!request) {
            return res.status(404).json({ success: false, message: 'Заявка не найдена' });
        }
        await db.run('UPDATE requests SET status = ? WHERE id = ?', ['Принята', id]);
        res.json({ success: true });
    } catch (err) {
        console.error('Ошибка обновления заявки:', err);
        res.status(500).json({ success: false, message: 'Ошибка обновления заявки' });
    }
});

app.put('/api/requests/:id/reject', ensureAuthenticated, async (req, res) => {
    const id = req.params.id;
    try {
        const request = await db.get('SELECT * FROM requests WHERE id = ?', [id]);
        if (!request) {
            return res.status(404).json({ success: false, message: 'Заявка не найдена' });
        }
        await db.run('UPDATE requests SET status = ? WHERE id = ?', ['Отклонена', id]);
        res.json({ success: true });
    } catch (err) {
        console.error('Ошибка обновления заявки:', err);
        res.status(500).json({ success: false, message: 'Ошибка обновления заявки' });
    }
});

app.listen(port, () => {
    console.log(`Сервер запущен на http://localhost:${port}`);
});

