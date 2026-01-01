const express = require('express');
const app = express();
const PORT = 3000;

app.get('/', (req, res) => {
    console.log('Got request to /');
    res.send('Hello World');
});

app.get('/login', (req, res) => {
    console.log('Got request to /login');
    res.send('<h1>Login Page</h1>');
});

const server = app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

process.on('SIGINT', () => {
    console.log('SIGINT received');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});
