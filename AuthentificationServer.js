const httpsJS = require('https');
const pathJS = require('path');
const fileSysJS = require('fs');
const argon2JS = require('argon2');
const expressJS = require('express');
const readlineJS = require('readline');

const jwtJS = require('jsonwebtoken');


const expressApp = expressJS();

expressApp.use(expressJS.json());



const tokenSecret = 'GEI761'
const refreshTokenSecret = 'REF_GEI761'




expressApp.post('/api/v1/users', async (request, response) => {
    try {
        //verify if the email already in use
        

        const userExists = await checkUserExistence(request.body.email);
        if (userExists) {
            console.log(`LOGIN ATTEMPT FROM EXISTED EMAIL : ${request.body.email}`);
            return response.status(400).send('This email already in use');
        }
        //verify the password
        if (!isPasswordValid(request.body.password)) {
            console.log('Invalid password format');
            response.status(400).send('Invalid password format');
            return;
        }

        const hashedPassword = await argon2JS.hash(request.body.password, {
            type: argon2JS.argon2id,
        });

        
       
        const newUser = {
            email: request.body.email,
            password: hashedPassword,
           
        };

        saveUserToFile(newUser);
        console.log(`New user has been Created @ ${newUser.email}`);
        response.send(newUser);

    } catch {
        response.status(500);
    }
});

expressApp.post('/api/v1/login', async (request,response) => {
    const userData = {
        email: request.body.email,
        password: request.body.password
    };
    //verify if the user existe
    
    const userExists = await checkUserExistence(userData.email);

    if (userExists) {
        //verify the password
        console.log(`NEW LOGIN ATTEMPT FROM : ${userData.email} `);
        const passwordMatch = await verifyPassword(userData.email, userData.password);

        if (passwordMatch) {
            console.log(`PASSWORD CORRECT : ${userData.email} `);
           
           
            const token = generatetoken(userData);
            const refreshToken = generateRefreshToken(userData.email);

            saveRefreshTokenToFile(refreshToken);
            response.send({
                email: userData,
                token: token,
                refreshToken: refreshToken
            });
        } else {
            console.log(`PASSWORD INCORRECT ${userData.password}`);
            response.status(401).send("Unauthorized");
        }
    } else {
        console.log(`User ${userData.email} does not exist`);
        response.status(401).send("Unauthorized");
    }
});
expressApp.post('/api/v1/token', async (request, response) => {
    
    const requestToken = request.body.token;
    if (requestToken == null) return response.sendStatus(401); 

    const tokenExists = await checkTokenExistence(requestToken);

    console.log(requestToken);
    if (tokenExists) {
        console.log('token existe');
        jwtJS.verify(requestToken, refreshTokenSecret, (err, decoded) => {
            if (err) {
                response.status(401).send('Invalid token');
            } else {
                // Token is valid, perform authorized actions
                const newAccesToken = generatetoken(decoded.email);
                return response.status(200).send({ token: newAccesToken });


            }
        });

    } else {
        return response.sendStatus(401);
    }
});
expressApp.delete('/api/v1/logout', async (request, response) => {

    const authorizationHeader = request.headers['authorization'];

    if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
        return response.status(401).json({ success: false, message: 'Unauthorized: Token is not provided' });
    }

    const token = authorizationHeader.substring(7); // Remove 'Bearer ' from the beginning

    if (token) {

        
        jwtJS.verify(token, refreshTokenSecret, (err, decoded) => {
            if (err) {
                response.status(401).json({ success: false, message: 'Invalid token' });
            } else {
                
                deleteToken(token)
                response.sendStatus(204);
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


sslEncryptedServer.listen(2001, () => console.log('listening on port 2001 .........')); 

async function deleteToken(token) {

    const fileStream = fileSysJS.createReadStream('refresh_tokens.txt');
    const rl = readlineJS.createInterface({
        input: fileStream,
        crlfDelay: Infinity,
    });
    let fileContent = '';
    for await (const line of rl) {
        if (line.includes(`TOKEN : ${token}`)) {

            
        } else {
            fileContent += line + '\n';
            console.log('Line' + fileContent);
        }
    }
    fileSysJS.writeFile('refresh_tokens.txt', fileContent, 'utf8', (err) => {
        if (err) {
            console.error('Error writing file:', err);
        } else {
            console.log(`Lines containing 'TOKEN ' deleted`);
        }
    });

    


}
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
    const userDataTxt = `EMAIL : ${user.email} | PASSWORD : ${user.password}\n`;

    
    fileSysJS.appendFile('user_data.txt', userDataTxt, (err) => {
        if (err) {
            console.error("Error saving user data to file:", err);
        } else {
            console.log("User data saved to file");
        }
    });
}
function saveRefreshTokenToFile(RefreshToken) {
    const userDataTxt = `TOKEN : ${RefreshToken}`;


    fileSysJS.appendFile('refresh_tokens.txt', userDataTxt, (err) => {
        if (err) {
            console.error("Error saving token to file:", err);
        } else {
            console.log("Refresh token saved to file");
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
           
            return true;
        }
    }

    
    return false;
}
async function checkTokenExistence(refToken) {
    const fileStream = fileSysJS.createReadStream('refresh_tokens.txt');
    const rl = readlineJS.createInterface({
        input: fileStream,
        crlfDelay: Infinity,
    });

    for await (const line of rl) {
        if (line.includes(`TOKEN : ${refToken}`)) {
           
            return true;
        }
    }

    
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
            
            const storedPassword = line.match(/PASSWORD : (.*)/)[1];

            
            const passwordMatch = await argon2JS.verify(storedPassword, password);
            return passwordMatch;
        }
    }

   
    return false;
}

function generatetoken(userData) {
    const expiresIn = '100d';
    return jwtJS.sign({ email: userData.email }, tokenSecret, { expiresIn });
}
function generateRefreshToken(userEmail) {
    return jwtJS.sign({ email: userEmail }, refreshTokenSecret);
}