
const httpsJS = require('https');
const pathJS = require('path');
const fileSysJS = require('fs');


const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJpYXQiOjE3MDU3MDA5NzIsImV4cCI6MTcwNTcwMDk5Mn0.xaoYQIfLmkKEb6BErSzp8xLjUJY5_S4JnpeqS1pm10E'
const getRequestOptions = {
    port: 2000,
    hostname: 'localhost',
    path: '/api/v1/user',
    key: fileSysJS.readFileSync(pathJS.join(__dirname, 'certificate', 'client-key.key')),
    cert: fileSysJS.readFileSync(pathJS.join(__dirname, 'certificate', 'client-cert.pem')),
    ca: [fileSysJS.readFileSync(pathJS.join(__dirname, 'certificate', 'server-cert.pem'))], // Specify the CA certificate for server verification
    passphrase : 'gei761',
    method: 'GET',
    headers: {
        'Authorization': `Bearer ${token}`,
    },
    rejectUnauthorized: false
};




//createUser('user@example.com', 'Password1234@-4');
loginUser('user@example.com', 'Password1234@-4');
getUserData(token);




function createUser(email, password) {
    const options = {
        hostname: 'localhost',
        port: 2001, // Replace with the port your server is running on
        path: '/api/v1/users',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        key: fileSysJS.readFileSync(pathJS.join(__dirname, 'certificate', 'client-key.key')),
        cert: fileSysJS.readFileSync(pathJS.join(__dirname, 'certificate', 'client-cert.pem')),
        ca: [fileSysJS.readFileSync(pathJS.join(__dirname, 'certificate', 'server-cert.pem'))], // Specify the CA certificate for server verification
        passphrase: 'gei761',
        rejectUnauthorized: false,
    };

    const req = httpsJS.request(options, (res) => {
        console.log('statusCode:', res.statusCode);
        console.log('headers:', res.headers);

        res.on('data', (data) => {
            console.log('Response:', data.toString());
        });
    });

    req.on('error', (error) => {
        console.error('Error:', error);
    });

    const userData = JSON.stringify({ email, password });

    req.write(userData);
    req.end();
}
function loginUser(email, password) {
    const options = {
        hostname: 'localhost',
        port: 2001, // Replace with the port your server is running on
        path: '/api/v1/login',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        key: fileSysJS.readFileSync(pathJS.join(__dirname, 'certificate', 'client-key.key')),
        cert: fileSysJS.readFileSync(pathJS.join(__dirname, 'certificate', 'client-cert.pem')),
        ca: [fileSysJS.readFileSync(pathJS.join(__dirname, 'certificate', 'server-cert.pem'))], // Specify the CA certificate for server verification
        passphrase: 'gei761',
        rejectUnauthorized: false,
    };

    const req = httpsJS.request(options, (res) => {
        console.log('statusCode:', res.statusCode);
        console.log('headers:', res.headers);

        res.on('data', (data) => {
            

            
            const jsonResponse = JSON.parse(data);

            
            const token = jsonResponse.token;
            console.log('Response:', token);

            getUserData(token);//Getting the user data after passing the token
            
        });
    });

    req.on('error', (error) => {
        console.error('Error:', error);
    });

    const userData = JSON.stringify({ email, password });

    req.write(userData);
    req.end();
}
function getUserData(token) {
    const options = {
        hostname: 'localhost',
        port: 2000, // Replace with the port your server is running on
        path: '/api/v1/user',
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${token}`,
        },
        key: fileSysJS.readFileSync(pathJS.join(__dirname, 'certificate', 'client-key.key')),
        cert: fileSysJS.readFileSync(pathJS.join(__dirname, 'certificate', 'client-cert.pem')),
        ca: [fileSysJS.readFileSync(pathJS.join(__dirname, 'certificate', 'server-cert.pem'))], // Specify the CA certificate for server verification
        passphrase: 'gei761',
        rejectUnauthorized: false,
    };

    const req = httpsJS.request(options, (res) => {
        console.log('statusCode:', res.statusCode);
        console.log('headers:', res.headers);

        res.on('data', (data) => {
            console.log('Response:', data.toString());
        });
    });

    req.on('error', (error) => {
        console.error('Error:', error);
    });

    req.end();
}


