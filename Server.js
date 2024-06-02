const httpsJS = require('https');
const pathJS = require('path');
const fileSysJS = require('fs');
const argon2JS = require('argon2');
const expressJS = require('express');
const readlineJS = require('readline');
const sessionJS = require('express-session');
const jwtJS = require('jsonwebtoken');
const cryptoJS = require('crypto');

const expressApp = expressJS();

expressApp.use(expressJS.json());



const tokenSecret = 'GEI761'

expressApp.get('/api/v1/user', (request, response) => {

    const authorizationHeader = request.headers['authorization'];

    if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
        return response.status(401).json({ success: false, message: 'Unauthorized: Token is not provided' });
    }

    const token = authorizationHeader.substring(7); // Remove 'Bearer ' from the beginning

    
   

    
    if (token) {

        // Verify the token
        jwtJS.verify(token, tokenSecret, (err, decoded) => {
            if (err) {
                response.status(401).json({ success: false, message: 'Invalid token' });
            } else {
                // Token is valid, perform authorized actions
                
                response.send('Get request working fine');
                response.end();
                console.log('New request ');
            }
        });


    } else {
        response.status(401).send('Unautherized : token is not provided');
    }
       



   

});








const sslEncryptedServer = httpsJS.createServer(
    {
        key: fileSysJS.readFileSync(pathJS.join(__dirname, 'certificate', 'privatekey.pem')),
        cert: fileSysJS.readFileSync(pathJS.join(__dirname, 'certificate', 'certificate.pem')),
        ca: [
            fileSysJS.readFileSync(pathJS.join(__dirname, 'certificate', 'client-cert.pem'))
        ],// because it is a self signed, not from a certificate authority
        requestCert: false,
        rejectUnauthorized: false,
    },
    expressApp
);


sslEncryptedServer.listen(2000, () => console.log('listening on port 2000 .........')); 


function isPasswordValid(password) {
    // Minimum length of 8 characters
    const minLength = 8;

    // Include at least one lowercase letter
    const hasLowerCase = /[a-z]/.test(password);

    // Include at least one uppercase letter
    const hasUpperCase = /[A-Z]/.test(password);

    // Include at least one digit
    const hasDigit = /\d/.test(password);
    
    // Include at least one special character 
    const hasSpecialChar = /[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]/.test(password);

    // Combine all conditions
    const isPasswordValid =
        password.length >= minLength &&
        hasLowerCase &&
        hasUpperCase &&
        hasDigit &&
        hasSpecialChar;

    return isPasswordValid;
};
function saveUserToFile(user) {
    const userDataTxt = `
    ================================================================NEW USER ==============================================================\n
     EMAIL : ${user.email} | PASSWORD : ${user.password}\n
    =======================================================================================================================================`;

    
    fileSysJS.appendFile('user_data.txt', userDataTxt, (err) => {
        if (err) {
            console.error("Error saving user data to file:", err);
        } else {
            console.log("User data saved to file");
        }
    });
}

async function checkUserExistence(email) {
    const fileStream = fileSysJS.createReadStream('user_data.txt');
    const rl = readlineJS.createInterface({ 
        input: fileStream,
        crlfDelay: Infinity,
    });

    for await (const line of rl) {
        if (line.includes(`EMAIL : ${email}`)) {
            // User found in the file
            return true;
        }
    }

    // User not found in the file
    return false;
}

async function verifyPassword(email, password) {
    const fileStream = fileSysJS.createReadStream('user_data.txt');
    const rl = readlineJS.createInterface({
        input: fileStream,
        crlfDelay: Infinity,
    });

    for await (const line of rl) {
        if (line.includes(`EMAIL : ${email}`)) {
            // Extract stored hashed password
            const storedPassword = line.match(/PASSWORD : (.*)/)[1];

            // Check if the provided password matches the stored hashed password
            const passwordMatch = await argon2JS.verify(storedPassword, password);
            return passwordMatch;
        }
    }

    // User not found in the file
    return false;
}